import re
from urllib.parse import urlparse

IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")

def detect_type_and_value(item):
    """
    Accepts a raw feed item: can be dict or string.
    Returns list of normalized (type, value, meta) tuples.
    """
    results = []
    if isinstance(item, dict):
        # common keys: ip, domain, url, hash, md5, sha1, sha256
        for k in ["ip", "ipv4", "src_ip", "destination_ip", "domain", "url", "hash", "md5", "sha1", "sha256", "indicator"]:
            if k in item and item[k]:
                val = str(item[k]).strip()
                if IPV4_RE.search(val):
                    results.append(("ip", val, item))
                elif any(c in val for c in [".", "/"]) and not IPV4_RE.search(val):
                    if val.startswith("http"):
                        # possible url
                        parsed = urlparse(val)
                        domain = parsed.netloc or val
                        results.append(("domain", domain, item))
                    else:
                        results.append(("domain", val, item))
                else:
                    # fallback: treat as hash or generic
                    if SHA256_RE.search(val):
                        results.append(("hash", val, item))
                    elif MD5_RE.search(val) or SHA1_RE.search(val):
                        results.append(("hash", val, item))
                    else:
                        results.append(("unknown", val, item))
        return results

    text = str(item).strip()
    # IPs
    for m in IPV4_RE.findall(text):
        results.append(("ip", m, {"raw": text}))
    # hashes
    for m in SHA256_RE.findall(text):
        results.append(("hash", m, {"raw": text}))
    for m in SHA1_RE.findall(text):
        results.append(("hash", m, {"raw": text}))
    for m in MD5_RE.findall(text):
        results.append(("hash", m, {"raw": text}))
    # domains (naive: extract tokens containing a dot and letters)
    tokens = re.findall(r"\b[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}\b", text)
    for t in tokens:
        if IPV4_RE.match(t):
            continue
        results.append(("domain", t, {"raw": text}))
    return results
