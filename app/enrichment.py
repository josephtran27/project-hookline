import os
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

async def enrich_ip(client: httpx.AsyncClient, ip: str) -> dict:
    """
    Checks an IP address against the AbuseIPDB v2 API.
    """
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your-abuseipdb-api-key":
        return {"ip": ip, "abuse_score": 0, "status": "no_api_key"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = await client.get(url, headers=headers, params=params, timeout=5.0)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "is_public": data.get("isPublic", True),
                "country": data.get("countryCode", "Unknown"),
                "status": "success"
            }
    except Exception:
        pass
    return {"ip": ip, "abuse_score": 0, "status": "error"}

async def enrich_hash(client: httpx.AsyncClient, file_hash: str) -> dict:
    """
    Checks a file SHA-256 hash against the VirusTotal v3 API.
    """
    if not VT_API_KEY or VT_API_KEY == "your-virustotal-api-key":
        return {"hash": file_hash, "malicious_count": 0, "status": "no_api_key"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = await client.get(url, headers=headers, timeout=5.0)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_votes = stats.get("malicious", 0)
            return {
                "hash": file_hash,
                "malicious_count": malicious_votes,
                "status": "success"
            }
        elif response.status_code == 404:
            return {"hash": file_hash, "malicious_count": 0, "status": "not_found_on_vt"}
    except Exception:
        pass
    return {"hash": file_hash, "malicious_count": 0, "status": "error"}

async def enrich_all_iocs(iocs: dict) -> dict:
    """
    Fires asynchronous requests concurrently for all extracted IPs and attachment hashes.
    """
    enriched_results = {
        "ips": [],
        "hashes": []
    }

    async with httpx.AsyncClient() as client:
        ip_tasks = [enrich_ip(client, ip) for ip in iocs.get("ips", [])]
        hash_tasks = [enrich_hash(client, item["sha256"]) for item in iocs.get("hashes", [])]

        # Execute all HTTP requests concurrently using clean asyncio.gather
        ip_results, hash_results = await asyncio.gather(
            asyncio.gather(*ip_tasks) if ip_tasks else asyncio.sleep(0),
            asyncio.gather(*hash_tasks) if hash_tasks else asyncio.sleep(0)
        )

        if ip_tasks and isinstance(ip_results, list):
            enriched_results["ips"] = list(ip_results)
        if hash_tasks and isinstance(hash_results, list):
            enriched_results["hashes"] = list(hash_results)

    return enriched_results