import requests
import json

def test_enrichment():
    try:
        print("[INFO] Fetching CVEs to test OTX enrichment...")
        response = requests.get("http://127.0.0.1:5000/api/cves")
        if response.status_code == 200:
            cves = response.json()
            print(f"[INFO] Found {len(cves)} CVEs. Checking for OTX data...")
            for cve in cves:
                if 'otx_pulses' in cve and cve['otx_pulses'] > 0:
                    print(f"  - {cve['cve_id']}: {cve['otx_pulses']} OTX pulses")
            print("[SUCCESS] Enrichment test complete.")
        else:
            print(f"[ERROR] Failed to fetch CVEs. Status code: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == '__main__':
    test_enrichment()
