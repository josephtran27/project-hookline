import re
import hashlib

def extract_ipv4(text: str) -> list:
    """
    Extracts valid IPv4 addresses from a given text string.
    """
    # Standard regex for IPv4
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    raw_ips = re.findall(ipv4_pattern, text)
    
    # Filter out invalid IPs (like 999.999.999.999)
    valid_ips = []
    for ip in raw_ips:
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            valid_ips.append(ip)
            
    return list(set(valid_ips)) # Return unique IPs only

def extract_urls(text: str) -> list:
    """
    Extracts URLs from plaintext or HTML body using a middle-ground regex.
    """
    # Regex to catch standard http/https links
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))

def hash_attachment(file_bytes: bytes) -> str:
    """
    Takes the raw bytes of an attachment and returns its SHA-256 hash.
    """
    sha256 = hashlib.sha256()
    sha256.update(file_bytes)
    return sha256.hexdigest()

def extract_all_iocs(parsed_email_data: dict) -> dict:
    """
    Master function to pull all IOCs from the parsed email components.
    """
    extracted_iocs = {
        "ips": [],
        "urls": [],
        "hashes": []
    }

    # 1. Extract IPs from the 'Received' header chain
    received_headers = " ".join(parsed_email_data.get("received_chain", []))
    extracted_iocs["ips"] = extract_ipv4(received_headers)

    # 2. Extract URLs from the body (combine plaintext and HTML)
    full_body = parsed_email_data.get("body_plaintext", "") + " " + parsed_email_data.get("body_html", "")
    extracted_iocs["urls"] = extract_urls(full_body)

    # 3. Hash the attachments
    for attachment in parsed_email_data.get("attachments", []):
        raw_bytes = attachment.get("raw_bytes")
        if raw_bytes:
            file_hash = hash_attachment(raw_bytes)
            extracted_iocs["hashes"].append({
                "filename": attachment["filename"],
                "sha256": file_hash
            })

    return extracted_iocs