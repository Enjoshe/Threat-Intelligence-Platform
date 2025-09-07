"""
Simple correlation logic:
- If two IoCs share the same IP or domain, create a correlation record (not implemented as separate table here)
- Also provide a function to match IoCs against a list of items (for example local logs)
"""

def correlate_iocs(iocs):
    """
    Input: list of IoC objects (ORM or dict-like)
    Returns: list of correlation tuples (type, value, related_ids)
    """
    seen = {}
    for i in iocs:
        key = (i.type, i.value)
        if key not in seen:
            seen[key] = []
        seen[key].append(i.id)
    correlations = []
    for k, ids in seen.items():
        if len(ids) > 1:
            correlations.append({"type": k[0], "value": k[1], "related_ids": ids})
    return correlations

def match_against_log(iocs, log_tokens):
    """
    Simple matching: if any IOC value (ip/domain/hash) appears in log_tokens, return matches.
    log_tokens: iterable of strings from logs
    """
    matches = []
    token_set = set(log_tokens)
    for i in iocs:
        if i.value in token_set:
            matches.append({"ioc_id": i.id, "type": i.type, "value": i.value})
    return matches
