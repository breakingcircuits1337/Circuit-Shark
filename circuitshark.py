import streamlit as st
import pandas as pd
import json
import time 
import subprocess
import tempfile
import os
import httpx
import asyncio
from collections import deque, Counter 
from datetime import datetime, timedelta 
import sqlite3 
import shutil 
import plotly.express as px 
import html 
import re 
import base64 
import ipaddress # For checking private/public IPs

WEASYPRINT_AVAILABLE = False
try:
    from weasyprint import HTML as WeasyHTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    pass 

# --- Configuration & Constants ---
APP_TITLE = "Circuit Shark 🦈"
LLM_OPTIONS = ["Google Gemini", "Mistral AI", "Groq", "All (Sequential)"] 
DEFAULT_LLM = "Google Gemini"
TSHARK_CMD = "tshark" 
NLP_HISTORY_LENGTH = 5 
DB_NAME = "circuit_shark_audit.db"
REPORT_FORMATS = ["Markdown", "HTML"]
if WEASYPRINT_AVAILABLE:
    REPORT_FORMATS.append("PDF")
TOP_N_STATS = 10
ABUSEIPDB_CACHE_EXPIRY_MINUTES = 60 # Cache AbuseIPDB results for 1 hour

# --- LLM API Keys & URLs ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "") 
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "") 
MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions" 
MISTRAL_DEFAULT_MODEL = "mistral-large-latest" 
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "") 
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions" 
GROQ_DEFAULT_MODEL = "llama3-8b-8192" 

# --- Threat Intelligence API Keys & URLs ---
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# --- Prompt Templates (Unchanged) ---
PROMPT_TEMPLATES = { # ... (same as v1.3)
    "general_analysis": ("Analyze the provided network packet data..."),
    "dns_focus": ("Examine the DNS traffic..."), "http_vulnerability_check": ("Inspect the HTTP traffic..."),
    "tls_analysis": ("Analyze the TLS handshake..."), "malware_communication_hunt": ("Scrutinize the packet data...")
}

# --- Database Setup and Helper Functions (Unchanged) ---
def init_db(): # Unchanged
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor() # ... (table creation logic)
    conn.commit(); conn.close()

def log_action(action_type, details_dict=None): # Unchanged
    try: # ... (logging logic)
        conn = sqlite3.connect(DB_NAME); cursor = conn.cursor() # ...
        conn.commit(); conn.close()
    except sqlite3.Error as e: st.caption(f"DB Log Err (Action): {e}")

def get_recent_actions_summary(limit=NLP_HISTORY_LENGTH): # Unchanged
    summary_lines = [] # ... (logic to fetch and format recent actions)
    return "\n".join(summary_lines)

def log_pcap_session(original_source_info, saved_filepath, filter_used, notes=""): # Unchanged
    try: # ... (logging logic)
        conn = sqlite3.connect(DB_NAME); cursor = conn.cursor() # ...
        pcap_session_id = cursor.lastrowid; conn.commit(); conn.close()
        log_action("SAVE_PCAP_SESSION_SUCCESS", {"saved_filepath": saved_filepath, "source": original_source_info, "notes": notes})
        return pcap_session_id
    except sqlite3.Error as e: st.error(f"DB Err saving PCAP: {e}"); return None

def log_llm_analysis(pcap_session_id, llm_name, template_key, query_addon, response_text, alerts_list): # Unchanged
    try: # ... (logging logic)
        conn = sqlite3.connect(DB_NAME); cursor = conn.cursor() # ...
        conn.commit(); conn.close()
    except sqlite3.Error as e: st.caption(f"DB Log Err (LLM Analysis): {e}")

# --- NLP Command Parsing LLM Call (Unchanged) ---
async def interpret_command_with_llm(user_command, command_history_str=""): # Unchanged
    # ... (same as v1.3)
    log_action("NLP_COMMAND_INTERPRET_START", {"command": user_command}) # ...
    if not GEMINI_API_KEY: return {"interpretation_notes": "NLP LLM (Gemini) not configured."} # ...
    return {"command_type": "analytical_query", "interpretation_notes": "Interpretation failed."} # Abridged

# --- Function to run tshark for field extraction (Unchanged) ---
def run_tshark_field_extraction(fields_to_extract, bpf_filter, pcap_file_path=None): # Unchanged
    # ... (same as v1.3)
    log_action("TSHARK_FIELD_EXTRACTION_START", {"fields": fields_to_extract}) # ...
    return None # Abridged

# --- Main LLM API Call Functions (Unchanged) ---
def parse_alerts_from_llm_text(llm_text, source_llm="LLM"): # Unchanged
    alerts = [] # ... (regex and fallback logic from v1.3)
    return alerts

async def call_gemini_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon): # Unchanged
    if not GEMINI_API_KEY: return {"text": "Gemini API Key not configured.", "alerts": []} # ...
    return {"text": "Gemini analysis text (abridged)", "alerts": []} # Abridged

async def call_mistral_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon): # Unchanged
    if not MISTRAL_API_KEY: return {"text": "Mistral API Key not configured.", "alerts": []} # ...
    return {"text": "Mistral analysis text (abridged)", "alerts": []} # Abridged

async def call_groq_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon): # Unchanged
    if not GROQ_API_KEY: return {"text": "Groq API Key not configured.", "alerts": []} # ...
    return {"text": "Groq analysis text (abridged)", "alerts": []} # Abridged

# --- Predefined Rules Engine (Unchanged) ---
PREDEFINED_RULES = [ # ... (same as v1.3)
    {"name": "Telnet Traffic Detected", "description": "Detects Telnet traffic...", "severity": "High", "conditions": lambda pkt_layers: "tcp" in pkt_layers and (pkt_layers["tcp"].get("tcp.port") == "23") and "telnet" in pkt_layers},
    # ... other rules
]
def check_predefined_rules(raw_packet_data_list): # Unchanged
    triggered_alerts = [] # ... (logic to apply rules from v1.3)
    return triggered_alerts

# --- Helper function to parse tshark -T ek JSON output (Unchanged) ---
def _extract_packet_details_from_ek(packet_json_str): # Unchanged
    # ... (same as v1.3)
    try: 
        packet_data = json.loads(packet_json_str); layers = packet_data.get("layers", {})
        summary = f"T:{packet_data.get('timestamp')} Proto:{layers.get('frame',{}).get('frame.protocols','N/A')}" # Abridged
        return {"summary": summary, "details": packet_data}
    except: return None

# --- Wireshark/tshark Interaction Functions (Unchanged from v1.4) ---
def _process_pcap_file_with_tshark(pcap_file_path, bpf_filter=None): # Unchanged
    # ... (same as v1.4)
    log_action("TSHARK_PROCESS_PCAP_START", {"pcap_path": pcap_file_path, "filter": bpf_filter}) # ...
    return f"Processed X packets from {os.path.basename(pcap_file_path)} (Filter: {bpf_filter or 'None'})." # Abridged

def start_live_capture(interface, capture_filter): # Unchanged
    # ... (same as v1.4)
    log_action("LIVE_CAPTURE_START", {"interface": interface, "filter": capture_filter}) # ...
    return f"Live capture started on {interface}." # Abridged

def stop_live_capture(bpf_filter_for_processing=None): # Unchanged
    # ... (same as v1.4)
    log_action("LIVE_CAPTURE_STOP_INITIATED") # ...
    return "Capture stopped & data processed." # Abridged

def process_pcap_file(uploaded_file, bpf_filter=None): # Unchanged
    # ... (same as v1.4)
    return "Processed uploaded PCAP." # Abridged

def get_tshark_summary_stats(pcap_file_path, bpf_filter=None): # Unchanged
    # ... (same as v1.4)
    log_action("TSHARK_QUICK_STATS_RUN", {"pcap_path": pcap_file_path, "filter": bpf_filter}) # ...
    return {"protocol_hierarchy": "Mock stats...", "ip_conversations": "Mock stats..."} # Abridged

# --- Reporting Engine (Unchanged) ---
def generate_html_report(analysis_results, user_query, packet_source, alerts_list, packet_summaries): # Unchanged
    return "<html><body>Report</body></html>" # Abridged
def format_markdown_report(analysis_results, user_query, packet_source, alerts_list, packet_summaries): # Unchanged
    return "# Report" # Abridged
def generate_pdf_from_html(html_string): # Unchanged
    return None # Abridged

# --- Traffic Statistics Functions (Unchanged) ---
def get_protocol_distribution(raw_packet_data): return Counter() # Unchanged, Abridged
def get_top_ips(raw_packet_data, ip_type="src", top_n=TOP_N_STATS): return [] # Unchanged, Abridged


# --- New: Threat Intelligence Functions ---
def is_public_ip(ip_address_str):
    """Checks if an IP address is public."""
    try:
        ip = ipaddress.ip_address(ip_address_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False # Not a valid IP address

async def check_ip_abuseipdb(ip_address):
    """Checks a public IP address against AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        # st.caption(f"AbuseIPDB API Key not set. Skipping check for {ip_address}.") # Can be noisy
        return None
    if not is_public_ip(ip_address):
        # st.caption(f"Skipping AbuseIPDB check for private/local IP: {ip_address}")
        return None

    # Check cache
    cached_data = st.session_state.abuseipdb_cache.get(ip_address)
    if cached_data and (datetime.now() - cached_data["timestamp"] < timedelta(minutes=ABUSEIPDB_CACHE_EXPIRY_MINUTES)):
        # st.caption(f"Using cached AbuseIPDB data for {ip_address}")
        return cached_data["data"]

    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': ''} # Add 'verbose' for more details if needed
    
    log_action("THREAT_INTEL_ABUSEIPDB_LOOKUP", {"ip": ip_address})
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(ABUSEIPDB_API_URL, headers=headers, params=params)
            response.raise_for_status()
            result = response.json()
            
            if result.get("data"):
                data = result["data"]
                # Store relevant fields
                intel_summary = {
                    "ipAddress": data.get("ipAddress"),
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "countryCode": data.get("countryCode"),
                    "usageType": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "totalReports": data.get("totalReports"),
                    "lastReportedAt": data.get("lastReportedAt")
                }
                st.session_state.abuseipdb_cache[ip_address] = {"timestamp": datetime.now(), "data": intel_summary}
                return intel_summary
            else: # No data in response, but successful call (e.g. IP not found in DB)
                st.session_state.abuseipdb_cache[ip_address] = {"timestamp": datetime.now(), "data": {"ipAddress": ip_address, "abuseConfidenceScore": 0, "totalReports": 0, "notes": "Not found in AbuseIPDB or no abuse reported."}}
                return st.session_state.abuseipdb_cache[ip_address]["data"]

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429: # Rate limit
            st.warning(f"AbuseIPDB rate limit hit. Skipping further checks for a while. IP: {ip_address}")
            # Optionally, add a flag to stop further checks for some time
            st.session_state.abuseipdb_rate_limited_until = datetime.now() + timedelta(minutes=15)
        elif e.response.status_code == 402: # Payment required (e.g. if using a paid feature on free key)
             st.warning(f"AbuseIPDB: Payment required or feature not available on current plan for IP: {ip_address}")
        else:
            st.caption(f"AbuseIPDB HTTP Error for {ip_address}: {e.response.status_code} - {e.response.text[:100]}")
    except httpx.RequestError as e:
        st.caption(f"AbuseIPDB Request Error for {ip_address}: {e}")
    except Exception as e:
        st.caption(f"Unexpected error checking AbuseIPDB for {ip_address}: {e}")
    return None # Indicate error or no data

async def run_threat_intelligence_checks():
    """Extracts unique public IPs and checks them against AbuseIPDB."""
    if not st.session_state.raw_packet_data:
        return

    if st.session_state.get("abuseipdb_rate_limited_until") and datetime.now() < st.session_state.abuseipdb_rate_limited_until:
        st.caption("AbuseIPDB checks paused due to rate limiting.")
        return

    unique_public_ips = set()
    for packet in st.session_state.raw_packet_data:
        layers = packet.get("details", {}).get("layers", {})
        src_ip, dst_ip = None, None
        if "ip" in layers:
            src_ip = layers["ip"].get("ip.src")
            dst_ip = layers["ip"].get("ip.dst")
        elif "ipv6" in layers:
            src_ip = layers["ipv6"].get("ipv6.src")
            dst_ip = layers["ipv6"].get("ipv6.dst")
        
        if src_ip and is_public_ip(src_ip): unique_public_ips.add(src_ip)
        if dst_ip and is_public_ip(dst_ip): unique_public_ips.add(dst_ip)

    if not unique_public_ips:
        st.session_state.ip_threat_intel_summary_message = "No unique public IPs found to check."
        return

    st.session_state.ip_threat_intel_results = st.session_state.get("ip_threat_intel_results", {})
    
    ips_to_check_this_run = [ip for ip in unique_public_ips if ip not in st.session_state.abuseipdb_cache or \
                             (datetime.now() - st.session_state.abuseipdb_cache[ip]["timestamp"] > timedelta(minutes=ABUSEIPDB_CACHE_EXPIRY_MINUTES))]
    
    if not ips_to_check_this_run and all(ip in st.session_state.abuseipdb_cache for ip in unique_public_ips):
        st.session_state.ip_threat_intel_summary_message = f"All {len(unique_public_ips)} unique public IPs already checked recently (cached)."
        # Ensure existing cached results are loaded into current session results if not already
        for ip in unique_public_ips:
            if ip not in st.session_state.ip_threat_intel_results and ip in st.session_state.abuseipdb_cache:
                st.session_state.ip_threat_intel_results[ip] = st.session_state.abuseipdb_cache[ip]["data"]
        return


    st.session_state.ip_threat_intel_summary_message = f"Checking {len(ips_to_check_this_run)} new/expired IPs out of {len(unique_public_ips)} unique public IPs..."
    
    # Use asyncio.gather for concurrent API calls
    # Batching might be needed if there are many unique IPs to avoid overwhelming the API or httpx client
    # For now, direct gather for simplicity.
    tasks = [check_ip_abuseipdb(ip) for ip in ips_to_check_this_run]
    results = await asyncio.gather(*tasks)
    
    flagged_count = 0
    for ip_intel in results:
        if ip_intel:
            st.session_state.ip_threat_intel_results[ip_intel["ipAddress"]] = ip_intel
            if ip_intel.get("abuseConfidenceScore", 0) >= 75: # Arbitrary threshold
                flagged_count += 1
                st.session_state.alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "Threat Intel (AbuseIPDB)",
                    "message": f"High abuse score ({ip_intel['abuseConfidenceScore']}%) for IP: {ip_intel['ipAddress']}. Country: {ip_intel.get('countryCode','N/A')}, Usage: {ip_intel.get('usageType','N/A')}, ISP: {ip_intel.get('isp','N/A')}, Reports: {ip_intel.get('totalReports',0)}",
                    "severity": "High"
                })
            elif ip_intel.get("abuseConfidenceScore", 0) >= 50:
                 st.session_state.alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source": "Threat Intel (AbuseIPDB)",
                    "message": f"Moderate abuse score ({ip_intel['abuseConfidenceScore']}%) for IP: {ip_intel['ipAddress']}. Check details.",
                    "severity": "Medium"
                })
    
    # Update summary message based on new checks
    newly_checked_count = len([res for res in results if res is not None])
    st.session_state.ip_threat_intel_summary_message = f"Checked {newly_checked_count} new/expired IPs. Total {len(st.session_state.ip_threat_intel_results)} unique public IPs now have intel. Flagged {flagged_count} IPs with high abuse score in this run."
    log_action("THREAT_INTEL_RUN_COMPLETED", {"unique_ips_total": len(unique_public_ips), "ips_checked_this_run": newly_checked_count, "flagged_this_run": flagged_count})


# --- Streamlit App UI ---
st.set_page_config(page_title=APP_TITLE, layout="wide")
if 'db_initialized' not in st.session_state: init_db(); st.session_state.db_initialized = True; log_action("APP_START")
st.title(f"{APP_TITLE} - Network Traffic Analysis with AI")

# Initialize session state (ensure all from v1.4 are present)
# ... (all from v1.4)
if 'abuseipdb_cache' not in st.session_state: st.session_state.abuseipdb_cache = {}
if 'ip_threat_intel_results' not in st.session_state: st.session_state.ip_threat_intel_results = {}
if 'ip_threat_intel_summary_message' not in st.session_state: st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."


async def main_ui():
    with st.sidebar:
        st.header("⚙️ Controls & Configuration")
        # ... (Alert Overview, API Key Checks, PCAP Storage, NLP Command Sections from v1.4)
        st.subheader("🚨 Alert Overview") # ...
        st.markdown("---") 
        # API Key Checks for all services
        if not ABUSEIPDB_API_KEY: st.caption("⚠️ AbuseIPDB Threat Intel limited (API key N/A).")
        if not MISTRAL_API_KEY: st.caption("⚠️ Mistral AI limited (API key N/A).") # ... (other LLM key checks)
        st.markdown("---") # ... (PCAP Storage, NLP, etc. from v1.4)

        st.subheader("📦 Packet Source")
        source_option = st.radio("Packet Source:", ("Live Capture", "Upload PCAP"), key="src_opt_radio_ti")
        # ... (Filter inputs as in v1.4)
        active_capture_filter_for_live = st.session_state.nlp_suggested_filter if st.session_state.nlp_suggested_filter else st.session_state.manual_capture_filter_value # ...

        if source_option == "Live Capture":
            # ... (Live capture controls from v1.4)
            if st.sidebar.button("🚀 Start", key="start_cap_ti"):
                # ...
                st.session_state.ip_threat_intel_results = {} # Clear old TI results on new capture
                st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
                # ...
            if st.sidebar.button("🛑 Stop", key="stop_cap_ti"):
                with st.spinner("Stopping capture and processing..."):
                    stop_live_capture(bpf_filter_for_processing=active_capture_filter_for_live)
                # Automatically run threat intel checks after stopping live capture and processing
                if st.session_state.raw_packet_data:
                    with st.spinner("Running threat intelligence checks..."):
                        await run_threat_intelligence_checks()
                    st.rerun() # To update the display with TI results/alerts

        elif source_option == "Upload PCAP":
            uploaded_file = st.file_uploader("Upload PCAP/NG", type=["pcap","pcapng","cap"], key="pcap_up_ti")
            st.session_state.pcap_processing_filter = st.text_input("BPF Filter for this PCAP (optional):", value=st.session_state.get("pcap_processing_filter",""), key="pcap_proc_filter_input_ti")
            if uploaded_file and st.button("📄 Process PCAP File", key="proc_pcap_ti"):
                with st.spinner(f"Processing {uploaded_file.name}..."):
                    # ... (reset states as in v1.4)
                    st.session_state.ip_threat_intel_results = {} 
                    st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
                    status = process_pcap_file(uploaded_file, bpf_filter=st.session_state.pcap_processing_filter)
                    st.success(status)
                    # ...
                # Automatically run threat intel checks after processing PCAP
                if st.session_state.raw_packet_data:
                    with st.spinner("Running threat intelligence checks..."):
                        await run_threat_intelligence_checks()
                    st.rerun()
        
        # Manual Threat Intel Check Button (could be useful if auto-run is disabled or for re-checks)
        if st.session_state.raw_packet_data:
            st.markdown("---")
            st.subheader("🛡️ Threat Intelligence")
            if st.button("Run/Refresh IP Threat Intel Checks", key="manual_ti_check_btn"):
                with st.spinner("Running threat intelligence checks..."):
                    await run_threat_intelligence_checks()
                st.rerun()
        
        st.markdown("---")
        st.subheader("🧠 LLM Analysis") # ... (LLM Analysis section from v1.4)
        st.subheader("📄 Reporting") # ... (Reporting section from v1.4)
        st.markdown("---"); st.caption(f"Circuit Shark v1.5 (Threat Intel)")


    # --- Main Area for Display ---
    # Display tshark -z Summary Stats (if generated)
    if st.session_state.get("tshark_summary_stats"): # ... (from v1.4)
        st.header("📈 tshark Summary Statistics") # ...
        st.markdown("---")
    
    # Display Traffic Analysis Dashboard (if data exists)
    if st.session_state.get("raw_packet_data"): # ... (from v1.4)
        st.header("📊 Traffic Analysis Dashboard") # ...
        st.markdown("---")

    # Display Quick Field Extraction Results (if generated)
    if st.session_state.field_extraction_df is not None and not st.session_state.field_extraction_df.empty: # ... (from v1.4)
        st.subheader("🔬 Quick Field Extraction Results"); st.dataframe(st.session_state.field_extraction_df) # ...
        st.markdown("---")

    # Main content columns for Packet Log, LLM Analysis & Alerts
    col1_main, col2_main = st.columns([2,3]) 
    with col1_main: 
        st.header("📦 Packet Data Log") # ... (Packet Log from v1.4)
        if st.session_state.selected_packet_index is not None: # Display Packet JSON and Threat Intel
            st.subheader(f"Pkt {st.session_state.selected_packet_index + 1} Details")
            try:
                selected_pkt_details = st.session_state.raw_packet_data[st.session_state.selected_packet_index]["details"]
                st.json(selected_pkt_details, expanded=False) # Start collapsed

                # Display Threat Intel for IPs in this selected packet
                packet_ips_to_show_intel = set()
                layers = selected_pkt_details.get("layers", {})
                if "ip" in layers:
                    if layers["ip"].get("ip.src"): packet_ips_to_show_intel.add(layers["ip"]["ip.src"])
                    if layers["ip"].get("ip.dst"): packet_ips_to_show_intel.add(layers["ip"]["ip.dst"])
                elif "ipv6" in layers:
                    if layers["ipv6"].get("ipv6.src"): packet_ips_to_show_intel.add(layers["ipv6"]["ipv6.src"])
                    if layers["ipv6"].get("ipv6.dst"): packet_ips_to_show_intel.add(layers["ipv6"]["ipv6.dst"])
                
                shown_intel_for_packet = False
                for ip_addr in packet_ips_to_show_intel:
                    if ip_addr in st.session_state.ip_threat_intel_results:
                        intel = st.session_state.ip_threat_intel_results[ip_addr]
                        if not shown_intel_for_packet:
                            st.markdown("---")
                            st.subheader("Threat Intelligence for IPs in this Packet:")
                            shown_intel_for_packet = True
                        
                        score = intel.get('abuseConfidenceScore', 0)
                        color = "green"
                        if score >= 75: color = "red"
                        elif score >= 50: color = "orange"
                        elif score > 0: color = "blue"
                        
                        with st.expander(f"Intel for {ip_addr} (Score: {score}%)", expanded=False):
                            st.markdown(f"<p style='color:{color};'>**Abuse Score: {score}%** (Reports: {intel.get('totalReports',0)})</p>", unsafe_allow_html=True)
                            st.write(f"Country: {intel.get('countryCode','N/A')}, ISP: {intel.get('isp','N/A')}")
                            st.write(f"Usage Type: {intel.get('usageType','N/A')}, Domain: {intel.get('domain','N/A')}")
                            st.write(f"Last Reported: {intel.get('lastReportedAt','N/A')}")
                            if intel.get("notes"): st.caption(intel.get("notes"))
            except IndexError: 
                st.error("Could not retrieve packet details."); st.session_state.selected_packet_index = None
            except Exception as e:
                st.error(f"Error displaying packet details/intel: {e}")

            if st.button("Close Details", key="close_pkt_det_main_dash_btn_ti"): st.session_state.selected_packet_index = None
            
    with col2_main: 
        st.header("💡 LLM Analysis & Alerts")
        # Display Threat Intel Summary Message
        if st.session_state.get("ip_threat_intel_summary_message"):
            st.info(st.session_state.ip_threat_intel_summary_message)
            st.markdown("---")

        if st.session_state.alerts: # Alert display (unchanged from v1.3)
            st.subheader("🚨 Alerts!") # ...
            # ... (Logic to display sorted alerts with severity colors)
        if st.session_state.llm_analysis_results: # LLM insights display (unchanged)
            st.subheader("LLM Insights:") # ...
    
    st.markdown("---"); st.header("📋 Generated Report Preview") # Report Preview (unchanged)
    # ...
    st.markdown("---"); st.markdown(f"""<div style="text-align: center; font-size: small;"><p><strong>Disclaimer:</strong> Conceptual. LLM outputs require expert verification.</p></div>""", unsafe_allow_html=True)


if __name__ == "__main__":
    # Initialize all session state keys
    for key, default_value in { # Ensure all keys from v1.4 are here + new ones
        'is_capturing': False, 'raw_packet_data': [], 'captured_packets_log': [], 
        'llm_analysis_results': [], 'alerts': [], 'current_report_content': "",
        'packet_source_info': "N/A", 'tshark_process': None, 'temp_capture_file': None,
        'temp_capture_file_for_processing': None, 'last_processed_pcap_path': None,
        'selected_packet_index': None, 'current_prompt_template': "general_analysis",
        'nlp_suggested_filter': "", 'nlp_interpretation_notes': "", 
        'nlp_extracted_entities': {}, 'nlp_suggested_tshark_fields': [],
        'field_extraction_df': None, 
        'nlp_command_history': deque(maxlen=NLP_HISTORY_LENGTH),
        'current_pcap_session_id': None, 'pcap_save_dir': os.getcwd(),
        'manual_capture_filter_value': "", 'active_capture_filter': "",
        'usr_q_add_in': "", 'num_pkts_llm_in': 10,
        'current_report_format': "Markdown",
        'tshark_summary_stats': None, 
        'pcap_processing_filter': "",
        'abuseipdb_cache': {}, # New
        'ip_threat_intel_results': {}, # New
        'ip_threat_intel_summary_message': "Threat intelligence checks not yet run.", # New
        'abuseipdb_rate_limited_until': None # New
    }.items():
        if key not in st.session_state:
            st.session_state[key] = default_value
    
    asyncio.run(main_ui())
