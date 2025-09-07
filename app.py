import streamlit as st
import json
from core.db import DB
from core.models import IoC

st.set_page_config(page_title="Threat Intelligence Platform", layout="wide")

st.title("Threat Intelligence Platform")

# load config
try:
    with open("config.json", "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
except Exception:
    cfg = {"database_url": "sqlite:///threatintel.db"}

db = DB(cfg.get("database_url"))

st.sidebar.header("Controls")
limit = st.sidebar.number_input("Ioc rows", min_value=10, max_value=1000, value=200, step=10)
search = st.sidebar.text_input("Search value or type (ip/domain/hash)")

if st.sidebar.button("Refresh"):
    st.experimental_rerun()

iocs = db.list_iocs(limit=limit)
if search:
    iocs = [i for i in iocs if search.lower() in (i.value.lower() if i.value else "") or search.lower() in (i.type or "")]

st.write(f"Showing {len(iocs)} IOC entries")

cols = st.columns([1,2,1,2,2])
cols[0].markdown("**ID**")
cols[1].markdown("**Type**")
cols[2].markdown("**Value**")
cols[3].markdown("**Source**")
cols[4].markdown("**First Seen / Enriched**")

for i in iocs:
    row = st.columns([1,2,1,2,2])
    row[0].write(i.id)
    row[1].write(i.type)
    row[2].write(i.value)
    row[3].write(i.source)
    row[4].write(f"{i.first_seen} / {bool(i.enrichments)}")
    if st.button(f"Enrich {i.id}", key=f"enrich-{i.id}"):
        st.info("Enrichment must be run via backend script with API keys; see docs.")
        st.experimental_rerun()

st.sidebar.header("Quick Actions")
if st.sidebar.button("Run correlation (sample)"):
    import subprocess, sys
    st.sidebar.write("Run correlate script from backend")
    st.experimental_rerun()
