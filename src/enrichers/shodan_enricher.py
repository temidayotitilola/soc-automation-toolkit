import requests
from .. import config

def enrich_with_shodan(ioc: str) -> dict:
    """Query Shodan for IOC enrichment."""
    if not config.SHODAN_API_KEY:
        return {"error": "No Shodan API key configured"}

    url = f"https://api.shodan.io/shodan/host/{ioc}?key={config.SHODAN_API_KEY}"

    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ioc": ioc,
                "source": "Shodan",
                "org": data.get("org", "N/A"),
                "os": data.get("os", "N/A"),
                "ports": data.get("ports", [])
            }
        else:
            return {"error": f"Shodan error {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
