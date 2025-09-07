import requests
import csv
import json
import os
from urllib.parse import urlparse

def fetch_http_json(url, timeout=10):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    ct = r.headers.get("Content-Type", "")
    if "json" in ct or r.text.strip().startswith("{") or r.text.strip().startswith("["):
        return r.json()
    # attempt to parse text lines into list
    return r.text.splitlines()

def read_local_csv(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    rows = []
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
    return rows

def fetch_feed(feed):
    """
    feed is a dict with keys: name, type (http_json|http_text|local_file), url/path
    returns raw feed data
    """
    t = feed.get("type")
    if t == "http_json":
        return fetch_http_json(feed.get("url"))
    if t == "http_text":
        r = requests.get(feed.get("url"))
        r.raise_for_status()
        return r.text.splitlines()
    if t == "local_file":
        path = feed.get("path")
        _, ext = os.path.splitext(path or "")
        if ext.lower() in [".csv"]:
            return read_local_csv(path)
        else:
            # return raw lines
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().splitlines()
    raise ValueError("Unknown feed type: " + str(t))
