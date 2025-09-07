"""
Very small script to demonstrate correlation and matching against a sample log.
"""
import argparse
import json
from core.db import DB
from core.correlator import correlate_iocs, match_against_log

def run(config_path):
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    db = DB(cfg.get("database_url", "sqlite:///threatintel.db"))
    iocs = db.list_iocs(limit=1000)
    corrs = correlate_iocs(iocs)
    print("Correlations found:", corrs)

    # sample log tokens (in practice parse your logs)
    sample_tokens = ["1.2.3.4", "malicious.example.com", "abcdef123456"]
    matches = match_against_log(iocs, sample_tokens)
    print("Matches against sample log:", matches)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    run(args.config)
