"""
Script to ingest configured feeds into the DB.
Usage: python run_ingest.py --config config.json
"""
import argparse
import json
from core.fetcher import fetch_feed
from core.parser import detect_type_and_value
from core.db import DB

def ingest(config_path):
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    db = DB(cfg.get("database_url", "sqlite:///threatintel.db"))
    feeds = cfg.get("feeds", [])
    for feed in feeds:
        print("Fetching feed:", feed.get("name"))
        try:
            raw = fetch_feed(feed)
            # raw can be list/dict/lines
            if isinstance(raw, dict):
                items = [raw]
            else:
                items = raw
            for item in items:
                parsed = detect_type_and_value(item)
                for typ, val, meta in parsed:
                    if typ in ("ip", "domain", "hash"):
                        db.upsert_ioc(typ, val, feed.get("name"), meta)
        except Exception as e:
            print("Failed feed", feed.get("name"), ":", e)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    ingest(args.config)
