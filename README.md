# Threat Intelligence Platform

## Overview
A platform that aggregates multiple threat feeds and correlates indicators of compromise (IOCs) to provide actionable alerts.

## Features
- Ingest IOCs from sources such as AlienVault OTX and AbuseIPDB
- Normalize and deduplicate threat data
- Correlate IPs, hashes, and domains with local logs
- Dashboard for visualizing current active threats

## Tech Stack
- Python, Flask/FastAPI
- SQLite or PostgreSQL
- Pandas
- Streamlit

## Future Work
- Integration with SIEM tools (Splunk, ELK)
- Enrichment with VirusTotal API
- Automated alerts (email/Slack)

## Status
In progress – feed ingestion prototype implemented
