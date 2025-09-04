import json
import requests
from . import config

def send_to_splunk(event: dict) -> None:
    """Send enriched event to Splunk via HEC."""
    headers = {
        "Authorization": f"Splunk {config.SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {"event": event}
    try:
        response = requests.post(
            config.SPLUNK_HEC_URL,
            headers=headers,
            data=json.dumps(payload),
            verify=False
        )
        if response.status_code == 200:
            print("[+] Successfully sent to Splunk:", event)
        else:
            print("[-] Splunk HEC Error:", response.text)
    except Exception as e:
        print("[-] Failed to send to Splunk:", str(e))
