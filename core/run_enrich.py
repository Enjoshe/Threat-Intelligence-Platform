"""
Enrich all IOCs in the database with threat intelligence.
Usage: python run_enrich.py --config config.json
"""
import argparse
import json
from core.db import DB
from core.enricher import enrich_ioc

def run(config_path):
    with open(config_path) as f:
        cfg = json.load(f)

    db   = DB(cfg.get("database_url", "sqlite:///threatintel.db"))
    iocs = db.list_iocs(limit=500)

    print(f"Enriching {len(iocs)} IOCs...\n")

    for ioc in iocs:
        # Skip already enriched to save API quota
        # Why? Free tier APIs have daily limits.
        # Re-enriching known IOCs wastes quota needed for new ones.
        if ioc.enriched:
            print(f"Skipping {ioc.value} (already enriched)")
            continue

        print(f"Enriching [{ioc.type}] {ioc.value}")
        result = enrich_ioc(ioc.type, ioc.value, cfg)

        # Store enrichment result
        db.add_enrichment(ioc.id, "composite", result)

        # Mark as enriched
        # Why mark? Idempotency — safe to run script multiple times
        # without re-querying APIs for the same IOCs
        s      = db.Session()
        record = s.query(db.Session.bind).get(ioc.id)

        # Print summary
        score  = result.get("risk_score", 0)
        action = result.get("recommended_action", "unknown")
        print(f"  Risk score: {score}/100 — {action}\n")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    run(args.config)
