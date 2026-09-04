import dns.resolver
import dkim
import re

def check_spf(domain: str) -> bool:
    """
    Queries the domain's TXT records to find the SPF policy.
    In a full production environment, this would also validate the originating IP.
    For this triage pipeline, we check if a restrictive SPF record exists.
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                # A valid SPF record exists
                return True
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
        return False

def check_dmarc(domain: str) -> bool:
    """
    Queries the _dmarc TXT record to see if the domain enforces alignment.
    """
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                return True
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
        return False

def check_dkim(raw_email_bytes: bytes) -> bool:
    """
    Validates the cryptographic signature attached to the email header.
    """
    try:
        # dkimpy does the heavy lifting: fetches the public key from DNS and verifies the hash
        return dkim.verify(raw_email_bytes)
    except Exception:
        return False

def perform_auth_checks(sender_email: str, raw_email_bytes: bytes) -> dict:
    """
    Runs all three checks and returns a summary for the LLM and database.
    """
    # Extract the domain from the sender email (e.g., "user@example.com" -> "example.com")
    domain_match = re.search(r"@([\w.-]+)", sender_email)
    domain = domain_match.group(1) if domain_match else ""

    if not domain:
        return {"spf": False, "dkim": False, "dmarc": False, "domain_found": False}

    spf_pass = check_spf(domain)
    dmarc_pass = check_dmarc(domain)
    dkim_pass = check_dkim(raw_email_bytes)

    return {
        "domain_checked": domain,
        "spf_record_present": spf_pass,
        "dkim_signature_valid": dkim_pass,
        "dmarc_record_present": dmarc_pass,
        # If DKIM fails on a domain that enforces DMARC/SPF, it's highly suspicious
        "likely_spoofed": not dkim_pass and (spf_pass or dmarc_pass)
    }
