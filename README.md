# Threat Intelligence Platform (TIP)

## Overview
A lightweight Threat Intelligence Platform that:
- Ingests open-source threat feeds or local feed files (IP addresses, domains, hashes).
- Normalizes and stores Indicators of Compromise (IoCs) in SQLite.
- Correlates IoCs with local log indicators and other IoCs.
- Optionally enriches IoCs using third-party APIs (VirusTotal).
- Provides a Streamlit dashboard for inspection and basic alerting.

This project is intended for learning and demonstration. For production use, harden the storage, secure API keys, and respect feed licensing.

