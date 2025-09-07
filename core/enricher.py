import requests
import os
import time

VT_BASE = "https://www.virustotal.com/api/v3"

def enrich_with_virustotal(ioc_type, value, api_key):
    """
    Minimal example: query VirusTotal for indicator.
    Requires API key in config. This is rate-limited; code implements a naive backoff.
    Returns a dict of selected attributes or None.
    """
    headers = {"x-apikey": api_key}
    if ioc_type == "ip":
        url = f"{VT_BASE}/ip_addresses/{value}"
    elif ioc_type == "domain":
        url = f"{VT_BASE}/domains/{value}"
    elif ioc_type == "hash":
        url = f"{VT_BASE}/files/{value}"
    else:
        return None
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            j = r.json()
            # Simplified extraction
            return {"vt_data": j}
        elif r.status_code == 429:
            # rate limited
            time.sleep(15)
            return enrich_with_virustotal(ioc_type, value, api_key)
        else:
            return {"error": f"vt_status:{r.status_code}"}
    except Exception as e:
        return {"error": str(e)}
