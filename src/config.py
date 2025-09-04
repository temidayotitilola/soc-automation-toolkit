import os
from dotenv import load_dotenv

load_dotenv()

# Splunk
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

# VirusTotal
VT_API_KEY = os.getenv("VT_API_KEY")

# Shodan
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
    raise ValueError("Missing Splunk HEC configuration in .env")
