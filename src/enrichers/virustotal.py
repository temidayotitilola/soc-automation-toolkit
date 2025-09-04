import requests
from .. import config

def enrich_with_virustotal(ioc: str) -> dict:
    """Query VirusTotal for IOC enrichment."""
    if not config.VT_API_KEY:
        return {"error": "No VirusTotal API key configured"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {"x-apikey": config.VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ioc": ioc,
                "source": "VirusTotal",
                "malicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            }
        else:
            return {"error": f"VirusTotal error {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
