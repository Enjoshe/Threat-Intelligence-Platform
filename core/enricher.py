# enricher.py
import requests
import time
import os

# ─────────────────────────────────────────────────────────
# Why three separate APIs?
# Each answers a different question:
# AbuseIPDB  → has this IP been reported for abuse? (reputation)
# OTX        → what threat actor/campaign is this IOC part of? (attribution)
# MISP       → what do our trusted private partners know about this? (private intel)
# Together they give high-confidence correlation no single source achieves.
# ─────────────────────────────────────────────────────────

# ── AbuseIPDB ─────────────────────────────────────────────

def enrich_abuseipdb(ip_address, api_key):
    """
    Query AbuseIPDB for IP reputation.

    Why AbuseIPDB?
    Crowdsourced database of reported malicious IPs. Gives confidence
    score, total reports, ISP, and usage type. ISP and usage type come
    from public WHOIS and BGP/ASN data that AbuseIPDB queries automatically.
    A datacenter IP with 80%+ confidence is almost certainly an attack server.

    Returns dict with reputation data or error.
    """
    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key":    api_key,
        "Accept": "application/json"
    }
    params  = {
        "ipAddress":    ip_address,
        "maxAgeInDays": 90,         # look back 90 days of reports
        "verbose":      True        # include individual report details
    }

    try:
        response = requests.get(url, headers=headers,
                                params=params, timeout=10)

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "provider":              "abuseipdb",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports":         data.get("totalReports", 0),
                "last_reported":         data.get("lastReportedAt"),
                "isp":                   data.get("isp"),
                "usage_type":            data.get("usageType"),
                "country_code":          data.get("countryCode"),
                "is_tor":                data.get("isTor", False),
                "is_public":             data.get("isPublic", True),
            }

        elif response.status_code == 429:
            # Rate limited — AbuseIPDB allows 1000 queries/day on free tier
            # Why sleep and retry? Losing enrichment data on a critical alert
            # is worse than a 60 second delay.
            print("  AbuseIPDB rate limited — waiting 60s")
            time.sleep(60)
            return enrich_abuseipdb(ip_address, api_key)

        else:
            return {"provider": "abuseipdb",
                    "error": f"HTTP {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"provider": "abuseipdb", "error": "timeout"}
    except Exception as e:
        return {"provider": "abuseipdb", "error": str(e)}


# ── AlienVault OTX ────────────────────────────────────────

def enrich_otx(ioc_type, value, api_key):
    """
    Query AlienVault OTX for threat intelligence.

    Why OTX?
    Community-driven platform where security researchers publish
    'pulses' — collections of IOCs grouped around specific threat
    actors or campaigns. OTX tells you WHO is behind an indicator
    and WHAT ELSE they use, which AbuseIPDB cannot.

    ioc_type: 'ip', 'domain', or 'hash'
    """

    # OTX uses different endpoint paths for different IOC types
    # Why map like this? OTX API design — each indicator type
    # has its own endpoint and response structure
    type_map = {
        "ip":     ("IPv4", "general"),
        "domain": ("domain", "general"),
        "hash":   ("file", "general"),
    }

    if ioc_type not in type_map:
        return {"provider": "otx", "error": f"unsupported type: {ioc_type}"}

    otx_type, section = type_map[ioc_type]
    url     = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/{section}"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()

            # Extract pulse information — this is the key intelligence
            # Pulses connect an IOC to a named threat actor or campaign
            pulses      = data.get("pulse_info", {}).get("pulses", [])
            pulse_names = [p.get("name") for p in pulses]
            pulse_tags  = list(set(
                tag for p in pulses
                for tag in p.get("tags", [])
            ))

            return {
                "provider":     "otx",
                "pulse_count":  len(pulses),
                "pulse_names":  pulse_names[:5],  # top 5 to avoid bloat
                "pulse_tags":   pulse_tags[:10],
                "reputation":   data.get("reputation", 0),
                "country":      data.get("country_name"),
                # Related IOCs from the same pulses
                # This enables pivoting — analyst can investigate
                # other infrastructure used by same actor
                "related_iocs": _extract_related_iocs(pulses)
            }

        elif response.status_code == 404:
            # Not found in OTX — not necessarily safe, just unknown
            return {"provider": "otx", "pulse_count": 0,
                    "reputation": 0, "note": "not found in OTX"}

        elif response.status_code == 429:
            print("  OTX rate limited — waiting 30s")
            time.sleep(30)
            return enrich_otx(ioc_type, value, api_key)

        else:
            return {"provider": "otx",
                    "error": f"HTTP {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"provider": "otx", "error": "timeout"}
    except Exception as e:
        return {"provider": "otx", "error": str(e)}


def _extract_related_iocs(pulses):
    """
    Extract related IOCs from pulse data for analyst pivoting.
    Pivoting means: this IP is in a pulse → what other IPs/domains
    are in that same pulse → investigate those too.
    """
    related = {"ips": set(), "domains": set(), "hashes": set()}

    for pulse in pulses[:3]:  # limit to top 3 pulses
        for indicator in pulse.get("indicators", [])[:20]:
            itype = indicator.get("type", "")
            ival  = indicator.get("indicator", "")
            if "IPv4" in itype:
                related["ips"].add(ival)
            elif "domain" in itype or "hostname" in itype:
                related["domains"].add(ival)
            elif "FileHash" in itype:
                related["hashes"].add(ival)

    return {
        "ips":     list(related["ips"])[:10],
        "domains": list(related["domains"])[:10],
        "hashes":  list(related["hashes"])[:10],
    }


# ── MISP ──────────────────────────────────────────────────

def enrich_misp(ioc_type, value, misp_url, misp_key):
    """
    Query a MISP instance for private threat intelligence.

    Why MISP?
    Unlike AbuseIPDB and OTX which are public, MISP is private —
    you join a trusted sharing community (e.g. automotive sector ISAC).
    Intelligence from trusted peers is higher confidence than public
    crowdsourced data because it comes from organizations with direct
    knowledge of attacks against your sector.

    misp_url: URL of your MISP instance e.g. https://misp.yourorg.com
    misp_key: your MISP API authentication key

    Note: for testing without a real MISP instance,
    this returns a stub response. Set misp_url to None to use stub.
    """

    # Stub mode for development/testing
    # Why stub? MISP requires a real instance to query.
    # During development and portfolio demonstration we simulate
    # the response structure so the pipeline still works end-to-end.
    if not misp_url or misp_url == "stub":
        return _misp_stub(ioc_type, value)

    headers = {
        "Authorization": misp_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json"
    }

    # MISP search endpoint
    search_url = f"{misp_url}/attributes/restSearch"
    payload    = {
        "value":       value,
        "type":        _misp_type(ioc_type),
        "returnFormat":"json",
        "limit":       10
    }

    try:
        response = requests.post(search_url, headers=headers,
                                 json=payload, timeout=10,
                                 verify=True)  # verify SSL cert

        if response.status_code == 200:
            data       = response.json()
            attributes = data.get("response", {}).get("Attribute", [])

            return {
                "provider":   "misp",
                "match_count": len(attributes),
                "matches": [
                    {
                        "event_id":  a.get("event_id"),
                        "comment":   a.get("comment"),
                        "timestamp": a.get("timestamp"),
                        "category":  a.get("category"),
                    }
                    for a in attributes[:5]
                ]
            }

        else:
            return {"provider": "misp",
                    "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"provider": "misp", "error": str(e)}


def _misp_type(ioc_type):
    """Map our IOC types to MISP attribute types"""
    return {
        "ip":     "ip-dst",
        "domain": "domain",
        "hash":   "md5"
    }.get(ioc_type, "other")


def _misp_stub(ioc_type, value):
    """
    Stub response for development without a real MISP instance.
    Returns realistic response structure for known test IOCs.
    """
    known_bad = {
        "45.33.32.156": {
            "match_count": 1,
            "matches": [{
                "event_id":  "1042",
                "comment":   "C2 server observed in automotive sector attack",
                "category":  "Network activity",
                "timestamp": "2026-04-17"
            }]
        }
    }

    if value in known_bad:
        result = known_bad[value].copy()
        result["provider"] = "misp"
        result["note"]     = "stub response — connect real MISP for production"
        return result

    return {
        "provider":    "misp",
        "match_count": 0,
        "note":        "stub response — not found in sample data"
    }


# ── Composite enrichment ──────────────────────────────────

def enrich_ioc(ioc_type, value, config):
    """
    Run all enrichment sources against a single IOC.
    Returns composite result with risk score.

    Why composite?
    No single source is fully reliable.
    AbuseIPDB can have false positives.
    OTX pulses can be low-quality.
    MISP might not have this IOC.
    Combining all three and scoring the result gives
    higher confidence than any individual source.
    """
    results = {}

    # Only query AbuseIPDB for IPs — it's IP-only
    if ioc_type == "ip":
        abuseipdb_key = config.get("abuseipdb_key")
        if abuseipdb_key:
            print(f"  Querying AbuseIPDB for {value}...")
            results["abuseipdb"] = enrich_abuseipdb(value, abuseipdb_key)

    # OTX handles IPs, domains, and hashes
    otx_key = config.get("otx_key")
    if otx_key:
        print(f"  Querying OTX for {value}...")
        results["otx"] = enrich_otx(ioc_type, value, otx_key)

    # MISP handles all types
    misp_url = config.get("misp_url", "stub")
    misp_key = config.get("misp_key", "")
    print(f"  Querying MISP for {value}...")
    results["misp"] = enrich_misp(ioc_type, value, misp_url, misp_key)

    # Calculate composite risk score
    results["risk_score"]          = calculate_risk_score(results, ioc_type)
    results["recommended_action"]  = get_recommended_action(results["risk_score"])

    return results


def calculate_risk_score(results, ioc_type):
    """
    Composite 0-100 risk score from all sources.

    Why weight them differently?
    AbuseIPDB score is already 0-100 and is well-calibrated —
    use it directly but cap its contribution at 50 points.
    OTX pulse count indicates how widely this IOC is known
    in the threat community — each pulse adds 10 points up to 30.
    MISP match means a trusted partner reported this IOC —
    private intel is high confidence so it contributes 20 points.
    """
    score = 0

    # AbuseIPDB contribution (up to 50 points)
    abuse_data = results.get("abuseipdb", {})
    if "abuse_confidence_score" in abuse_data:
        score += abuse_data["abuse_confidence_score"] * 0.5

    # OTX contribution (up to 30 points)
    otx_data = results.get("otx", {})
    pulse_count = otx_data.get("pulse_count", 0)
    score += min(pulse_count * 10, 30)

    # MISP contribution (20 points if any match)
    misp_data = results.get("misp", {})
    if misp_data.get("match_count", 0) > 0:
        score += 20

    return min(int(score), 100)


def get_recommended_action(risk_score):
    """
    Translate numeric score to actionable recommendation.

    Why discrete actions instead of just showing the number?
    Analysts shouldn't have to interpret a score under pressure.
    The platform should tell them what to do, not just what the number is.
    """
    if risk_score >= 80:
        return "BLOCK — high confidence malicious, immediate action required"
    elif risk_score >= 50:
        return "INVESTIGATE — multiple sources flag this, prioritize review"
    elif risk_score >= 20:
        return "MONITOR — some indicators present, watch for additional signals"
    else:
        return "LOW RISK — no significant threat intel matches"
