import argparse
from src.splunk_client import send_to_splunk
from src.enrichers.virustotal import enrich_with_virustotal
from src.enrichers.shodan_enricher import enrich_with_shodan

def main():
    parser = argparse.ArgumentParser(description="SOC Automation Toolkit")
    parser.add_argument("--ioc", required=True, help="Indicator of Compromise (e.g. IP, Domain, Hash)")
    args = parser.parse_args()

    ioc = args.ioc
    print(f"[+] Enriching IOC: {ioc}")

    # Collect enrichment data
    enrichment_results = {
        "ioc": ioc,
        "virustotal": enrich_with_virustotal(ioc),
        "shodan": enrich_with_shodan(ioc)
    }

    # Send to Splunk
    send_to_splunk(enrichment_results)

if __name__ == "__main__":
    main()
