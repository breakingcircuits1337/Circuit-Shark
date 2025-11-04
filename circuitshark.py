I apologize for the error. It seems I made a mistake in the tool call by directly referring to `default_api` instead of `tool_code` for the `natural_language_write_file` function. I will correct this and proceed with the requested changes.

Let's implement the rate limiting.

```python
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
import pyshark # NEW: Import pyshark for live capture
import threading # NEW: Import threading for background capture

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
IPGEOLOCATION_CACHE_EXPIRY_MINUTES = 1440 # Cache Geolocation results for 24 hours (less volatile)

# NEW: LLM Rate Limiting Delays
GEMINI_RATE_LIMIT_DELAY_MINUTES = 15
MISTRAL_RATE_LIMIT_DELAY_MINUTES = 15
GROQ_RATE_LIMIT_DELAY_MINUTES = 15


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
IPGEOLOCATION_API_KEY = os.environ.get("IPGEOLOCATION_API_KEY", "")
IPGEOLOCATION_API_URL = "https://api.ipgeolocation.io/ipgeo"

# --- MODIFIED: Prompt Templates ---
PROMPT_TEMPLATES = {
    "general_analysis": (
        "Analyze the provided network packet data for any signs of malicious activity, anomalies, or security risks. "
        "Focus on identifying potential threats, misconfigurations, or unusual communication patterns. "
        "Provide a summary of your findings, and if you find any specific, high-confidence threats, "
        "format them as an 'ALERT' on its own line, like this: \n"
        "ALERT: [Severity: High/Medium/Low] - [Description of the threat or finding] - [Packet number or IP address]\n"
        "Here is the packet data:"
    ),
    "dns_focus": (
        "Examine the DNS traffic in the provided packets. Look for signs of DNS tunneling, communication with known malicious domains, "
        "unusual query types (e.g., ANY, TXT for non-text purposes), or rapid-fire queries that might indicate DGA (Domain Generation Algorithm) activity. "
        "Format any high-confidence findings as an 'ALERT' line.\n"
        "Here is the packet data:"
    ),
    "http_vulnerability_check": (
        "Inspect the HTTP traffic for common web vulnerabilities. Look for signs of SQL injection (e.g., ' OR 1=1), "
        "Cross-Site Scripting (XSS) payloads (e.g., <script>), path traversal (e.g., ../../etc/passwd), "
        "or communication with suspicious User-Agents. "
        "Format any high-confidence findings as an 'ALERT' line.\n"
        "Here is the packet data:"
    ),
    "tls_analysis": (
        "Analyze the TLS handshake parameters. Look for weak cipher suites (e.g., RC4, 3DES), "
        "outdated TLS versions (e.g., SSLv3, TLS 1.0/1.1), self-signed certificates, "
        "or certificate mismatches (e.g., domain name vs. certificate subject). "
        "Format any high-confidence findings as an 'ALERT' line.\n"
        "Here is the packet data:"
    ),
    "malware_communication_hunt": (
        "Scrutinize the packet data for indicators of malware command-and-control (C2) communication. "
        "Look for long, high-entropy DNS queries, communication over non-standard ports (e.g., HTTP over 8080, 4444), "
        "suspicious beaconing (heartbeat) patterns (e.g., regular connections to the same IP), or cleartext indicators of known malware. "
        "Format any high-confidence findings as an 'ALERT' line.\n"
        "Here is the packet data:"
    ),
    "packet_translation": (
        "You are a network packet translator. Your task is to translate a single network packet, provided in JSON format, into a simple, human-readable summary. "
        "Do not analyze for threats. Do not look for vulnerabilities. "
        "Simply explain what this single packet is doing. "
        "Include: Who is the source? Who is the destination? What protocol is being used? What is the purpose of the packet (e.g., 'starting a connection', 'sending data', 'asking for a domain name')? "
        "Keep the explanation concise (2-3 sentences). \n\n"
        "Translate the following single packet:"
    )
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
    # ... (same as v1.6)
    log_action("NLP_COMMAND_INTERPRET_START", {"command": user_command}) # ...
    if not GEMINI_API_KEY: return {"interpretation_notes": "NLP LLM (Gemini) not configured."} # ...
    return {"command_type": "analytical_query", "interpretation_notes": "Interpretation failed."} # Abridged

# --- Function to run tshark for field extraction (Unchanged) ---
def run_tshark_field_extraction(fields_to_extract, bpf_filter, pcap_file_path=None): # Unchanged
    # ... (same as v1.6)
    log_action("TSHARK_FIELD_EXTRACTION_START", {"fields": fields_to_extract}) # ...
    return None # Abridged

# --- Main LLM API Call Functions ---
def parse_alerts_from_llm_text(llm_text, source_llm="LLM"): # Unchanged
    alerts = [] # ... (regex and fallback logic from v1.6)
    return alerts

async def call_gemini_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon):
    if st.session_state.get('gemini_rate_limited_until') and datetime.now() < st.session_state.gemini_rate_limited_until:
        return {"text": f"Gemini API is rate-limited. Please wait {round((st.session_state.gemini_rate_limited_until - datetime.now()).total_seconds() / 60)} minutes.", "alerts": []}
    if not GEMINI_API_KEY: 
        return {"text": "Gemini API Key not configured.", "alerts": []}
    
    headers = {
        "Content-Type": "application/json",
    }
    data = {
        "contents": [
            {
                "parts": [
                    {"text": constructed_prompt},
                    {"text": f"\n\n--- PACKET DATA ---\n{packet_data_json_list_str}"}
                ]
            }
        ]
    }
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}", headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            # Extract text from response
            candidates = response_json.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    llm_text = parts[0].get("text", "")
                    alerts = parse_alerts_from_llm_text(llm_text, "Google Gemini")
                    return {"text": llm_text, "alerts": alerts}
        return {"text": "Gemini: No text response from API.", "alerts": []}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            st.session_state.gemini_rate_limited_until = datetime.now() + timedelta(minutes=GEMINI_RATE_LIMIT_DELAY_MINUTES)
            log_action("LLM_RATE_LIMIT_HIT", {"llm": "Gemini", "status_code": 429})
            return {"text": f"Gemini API is rate-limited. Retrying in {GEMINI_RATE_LIMIT_DELAY_MINUTES} minutes.", "alerts": []}
        st.caption(f"Gemini HTTP Error: {e.response.status_code} - {e.response.text[:100]}", icon="❌")
        return {"text": f"Error calling Gemini API: {e}", "alerts": []}
    except httpx.RequestError as e:
        st.caption(f"Gemini Request Error: {e}", icon="❌")
        return {"text": f"Error calling Gemini API: {e}", "alerts": []}
    except Exception as e:
        st.caption(f"Gemini Unexpected Error: {e}", icon="❌")
        return {"text": f"An unexpected error occurred with Gemini: {e}", "alerts": []}

async def call_mistral_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon):
    if st.session_state.get('mistral_rate_limited_until') and datetime.now() < st.session_state.mistral_rate_limited_until:
        return {"text": f"Mistral API is rate-limited. Please wait {round((st.session_state.mistral_rate_limited_until - datetime.now()).total_seconds() / 60)} minutes.", "alerts": []}
    if not MISTRAL_API_KEY:
        return {"text": "Mistral API Key not configured.", "alerts": []}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {MISTRAL_API_KEY}"
    }
    messages = [
        {"role": "user", "content": constructed_prompt},
        {"role": "user", "content": f"\n\n--- PACKET DATA ---\n{packet_data_json_list_str}"}
    ]
    data = {
        "model": MISTRAL_DEFAULT_MODEL,
        "messages": messages,
        "temperature": 0.7,
        "random_seed": 1337
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(MISTRAL_API_URL, headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            choices = response_json.get("choices", [])
            if choices:
                llm_text = choices[0].get("message", {}).get("content", "")
                alerts = parse_alerts_from_llm_text(llm_text, "Mistral AI")
                return {"text": llm_text, "alerts": alerts}
        return {"text": "Mistral: No text response from API.", "alerts": []}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            st.session_state.mistral_rate_limited_until = datetime.now() + timedelta(minutes=MISTRAL_RATE_LIMIT_DELAY_MINUTES)
            log_action("LLM_RATE_LIMIT_HIT", {"llm": "Mistral AI", "status_code": 429})
            return {"text": f"Mistral API is rate-limited. Retrying in {MISTRAL_RATE_LIMIT_DELAY_MINUTES} minutes.", "alerts": []}
        st.caption(f"Mistral HTTP Error: {e.response.status_code} - {e.response.text[:100]}", icon="❌")
        return {"text": f"Error calling Mistral API: {e}", "alerts": []}
    except httpx.RequestError as e:
        st.caption(f"Mistral Request Error: {e}", icon="❌")
        return {"text": f"Error calling Mistral API: {e}", "alerts": []}
    except Exception as e:
        st.caption(f"Mistral Unexpected Error: {e}", icon="❌")
        return {"text": f"An unexpected error occurred with Mistral: {e}", "alerts": []}

async def call_groq_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon):
    if st.session_state.get('groq_rate_limited_until') and datetime.now() < st.session_state.groq_rate_limited_until:
        return {"text": f"Groq API is rate-limited. Please wait {round((st.session_state.groq_rate_limited_until - datetime.now()).total_seconds() / 60)} minutes.", "alerts": []}
    if not GROQ_API_KEY:
        return {"text": "Groq API Key not configured.", "alerts": []}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GROQ_API_KEY}"
    }
    messages = [
        {"role": "user", "content": constructed_prompt},
        {"role": "user", "content": f"\n\n--- PACKET DATA ---\n{packet_data_json_list_str}"}
    ]
    data = {
        "model": GROQ_DEFAULT_MODEL,
        "messages": messages,
        "temperature": 0.7
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(GROQ_API_URL, headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            choices = response_json.get("choices", [])
            if choices:
                llm_text = choices[0].get("message", {}).get("content", "")
                alerts = parse_alerts_from_llm_text(llm_text, "Groq")
                return {"text": llm_text, "alerts": alerts}
        return {"text": "Groq: No text response from API.", "alerts": []}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            st.session_state.groq_rate_limited_until = datetime.now() + timedelta(minutes=GROQ_RATE_LIMIT_DELAY_MINUTES)
            log_action("LLM_RATE_LIMIT_HIT", {"llm": "Groq", "status_code": 429})
            return {"text": f"Groq API is rate-limited. Retrying in {GROQ_RATE_LIMIT_DELAY_MINUTES} minutes.", "alerts": []}
        st.caption(f"Groq HTTP Error: {e.response.status_code} - {e.response.text[:100]}", icon="❌")
        return {"text": f"Error calling Groq API: {e}", "alerts": []}
    except httpx.RequestError as e:
        st.caption(f"Groq Request Error: {e}", icon="❌")
        return {"text": f"Error calling Groq API: {e}", "alerts": []}
    except Exception as e:
        st.caption(f"Groq Unexpected Error: {e}", icon="❌")
        return {"text": f"An unexpected error occurred with Groq: {e}", "alerts": []}


# --- Predefined Rules Engine ---
PREDEFINED_RULES = [ 
    {"name": "Telnet Traffic Detected", "description": "Detects Telnet traffic...", "severity": "High", "conditions": lambda pkt_layers: "tcp" in pkt_layers and (pkt_layers["tcp"].get("tcp.port") == "23") and "telnet" in pkt_layers},
    {"name": "FTP Traffic Detected", "description": "Detects FTP control traffic...", "severity": "Medium", "conditions": lambda pkt_layers: "tcp" in pkt_layers and (pkt_layers["tcp"].get("tcp.port") == "21") and "ftp" in pkt_layers},
    {"name": "SSH Traffic Detected", "description": "Detects SSH (secure shell) traffic...", "severity": "Low", "conditions": lambda pkt_layers: "tcp" in pkt_layers and (pkt_layers["tcp"].get("tcp.port") == "22") and "ssh" in pkt_layers},
    {"name": "SMB Traffic Detected", "description": "Detects SMB (Server Message Block) traffic...", "severity": "Medium", "conditions": lambda pkt_layers: "tcp" in pkt_layers and (pkt_layers["tcp"].get("tcp.port") == "445") and "smb" in pkt_layers},
    {"name": "Unusual DNS Query Length", "description": "Detects DNS queries longer than 60 characters, which can indicate tunneling or data exfiltration.", "severity": "Medium", "conditions": lambda pkt_layers: "dns" in pkt_layers and pkt_layers["dns"].get("dns.qry.name") and len(pkt_layers["dns"]["dns.qry.name"]) > 60},
    {"name": "HTTP POST to Unusual Port", "description": "Detects HTTP POST requests not on standard HTTP/S ports (80, 443, 8080, 8443).", "severity": "Low", "conditions": lambda pkt_layers: "http" in pkt_layers and pkt_layers["http"].get("http.request.method") == "POST" and "tcp" in pkt_layers and pkt_layers["tcp"].get("tcp.port") not in ["80", "443", "8080", "8443"]},
]

# MODIFIED: `check_predefined_rules` now expects a list of packet dictionaries,
# where each dictionary has a 'details' key with 'layers'.
def check_predefined_rules(raw_packet_data_list):
    triggered_alerts = []
    if not isinstance(raw_packet_data_list, list):
        raw_packet_data_list = [raw_packet_data_list] # Ensure it's a list even for single packet
    
    for i, packet_dict in enumerate(raw_packet_data_list):
        pkt_layers = packet_dict.get("details", {}).get("layers", {})
        
        # Determine packet number for context
        packet_number = i + 1
        if "frame" in pkt_layers and pkt_layers["frame"].get("frame.number"):
            packet_number = pkt_layers["frame"]["frame.number"]

        # Determine source/destination IP for context
        src_ip, dst_ip = "N/A", "N/A"
        if "ip" in pkt_layers:
            src_ip = pkt_layers["ip"].get("ip.src")
            dst_ip = pkt_layers["ip"].get("ip.dst")
        elif "ipv6" in pkt_layers:
            src_ip = pkt_layers["ipv6"].get("ipv6.src")
            dst_ip = pkt_layers["ipv6"].get("ipv6.dst")

        for rule in PREDEFINED_RULES:
            try:
                if rule["conditions"](pkt_layers):
                    alert_message = f"{rule['description']} Packet {packet_number} ({src_ip} -> {dst_ip})"
                    triggered_alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": f"Predefined Rule: {rule['name']}",
                        "message": alert_message,
                        "severity": rule["severity"],
                        "packet_info": {"number": packet_number, "src_ip": src_ip, "dst_ip": dst_ip}
                    })
            except Exception as e:
                st.sidebar.caption(f"Error applying rule '{rule['name']}': {e}")
    return triggered_alerts

# --- Helper function to parse tshark -T ek JSON output (Unchanged) ---
def _extract_packet_details_from_ek(packet_json_str): # Unchanged
    # ... (same as v1.6)
    try: 
        packet_data = json.loads(packet_json_str); layers = packet_data.get("layers", {})
        summary = f"T:{packet_data.get('timestamp')} Proto:{layers.get('frame',{}).get('frame.protocols','N/A')}" # Abridged
        return {"summary": summary, "details": packet_data}
    except: return None

# --- NEW: Function to process live packets in a separate thread ---
def _process_live_packet_stream():
    st.session_state.packets_in_live_capture = 0
    st.session_state.live_capture_pyshark_packets = [] # Store pyshark packet objects for later processing

    try:
        for pkt in st.session_state.tshark_process.sniff_continuously(packet_count=0): # packet_count=0 means infinite capture
            st.session_state.packets_in_live_capture += 1
            st.session_state.live_capture_pyshark_packets.append(pkt)

            # Convert pyshark packet to a simplified dict for rule checking
            # This conversion attempts to mimic _extract_packet_details_from_ek's output structure
            packet_dict = {
                "summary": f"T:{pkt.sniff_time} Proto:{pkt.highest_layer}",
                "details": {}
            }
            # Add common layers that predefined rules might check
            # This is a simplified approach, a full conversion would be more complex
            if hasattr(pkt, 'ip'):
                packet_dict["details"]["layers"] = packet_dict["details"].get("layers", {})
                packet_dict["details"]["layers"]["ip"] = {
                    "ip.src": pkt.ip.src,
                    "ip.dst": pkt.ip.dst,
                    "ip.proto": pkt.ip.proto
                }
            if hasattr(pkt, 'tcp'):
                packet_dict["details"]["layers"] = packet_dict["details"].get("layers", {})
                packet_dict["details"]["layers"]["tcp"] = {
                    "tcp.srcport": pkt.tcp.srcport,
                    "tcp.dstport": pkt.tcp.dstport,
                    "tcp.port": pkt.tcp.dstport # For rules that check generic "tcp.port"
                }
            if hasattr(pkt, 'udp'):
                packet_dict["details"]["layers"] = packet_dict["details"].get("layers", {})
                packet_dict["details"]["layers"]["udp"] = {
                    "udp.srcport": pkt.udp.srcport,
                    "udp.dstport": pkt.udp.dstport
                }
            if hasattr(pkt, 'dns'):
                packet_dict["details"]["layers"] = packet_dict["details"].get("layers", {})
                packet_dict["details"]["layers"]["dns"] = {
                    "dns.qry.name": pkt.dns.qry_name if hasattr(pkt.dns, 'qry_name') else None
                }
            if hasattr(pkt, 'http'):
                packet_dict["details"]["layers"] = packet_dict["details"].get("layers", {})
                packet_dict["details"]["layers"]["http"] = {
                    "http.request.method": pkt.http.request_method if hasattr(pkt.http, 'request_method') else None
                }
            
            # Add frame info for packet number
            packet_dict["details"]["layers"]["frame"] = packet_dict["details"]["layers"].get("frame", {})
            packet_dict["details"]["layers"]["frame"]["frame.number"] = str(st.session_state.packets_in_live_capture)


            triggered_alerts = check_predefined_rules([packet_dict]) # check rules against this single packet
            if triggered_alerts:
                st.session_state.alerts.extend(triggered_alerts)
                # st.experimental_rerun() # This might be too aggressive and lead to infinite loops/performance issues
                # For real-time updates, we'll rely on Streamlit's normal refresh cycle for now, 
                # or a timer-based rerun in the main thread if necessary.
                # A direct rerun from a thread is generally not recommended.

    except pyshark.capture.capture.TSharkCrashException as e:
        st.session_state.is_capturing = False
        st.session_state.tshark_process = None
        log_action("LIVE_CAPTURE_TSHARK_CRASH", {"error": str(e)})
        st.error(f"Live capture stopped due to TShark crash: {e}")
    except Exception as e:
        st.session_state.is_capturing = False
        st.session_state.tshark_process = None
        log_action("LIVE_CAPTURE_ERROR", {"error": str(e)})
        st.error(f"Error during live capture processing: {e}")

# --- Wireshark/tshark Interaction Functions ---
def _process_pcap_file_with_tshark(pcap_file_path, bpf_filter=None): # Unchanged
    # ... (same as v1.6)
    log_action("TSHARK_PROCESS_PCAP_START", {"pcap_path": pcap_file_path, "filter": bpf_filter}) # ...
    return f"Processed X packets from {os.path.basename(pcap_file_path)} (Filter: {bpf_filter or 'None'})." # Abridged

def start_live_capture(interface, capture_filter):
    if st.session_state.is_capturing:
        st.warning("Live capture is already running.")
        return

    st.session_state.is_capturing = True
    st.session_state.raw_packet_data = []  # Clear previous data
    st.session_state.captured_packets_log = []
    st.session_state.llm_analysis_results = []
    st.session_state.alerts = []
    st.session_state.tshark_summary_stats = None
    st.session_state.ip_threat_intel_results = {}
    st.session_state.ip_geolocation_results = {}
    st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
    st.session_state.packet_translation_output = ""
    st.session_state.last_translated_packet_index = None

    st.session_state.active_capture_interface = interface # Store interface
    st.session_state.active_capture_filter = capture_filter # Store filter

    try:
        # NEW: Initialize pyshark LiveCapture
        st.session_state.tshark_process = pyshark.LiveCapture(
            interface=interface, 
            bpf_filter=capture_filter, 
            use_json=True, 
            include_raw=True,
            # display_filter=capture_filter # Use display filter if bpf_filter is not enough
        )
        # NEW: Start the packet processing in a separate thread
        st.session_state.live_capture_thread = threading.Thread(target=_process_live_packet_stream, daemon=True)
        st.session_state.live_capture_thread.start()

        log_action("LIVE_CAPTURE_START", {"interface": interface, "filter": capture_filter})
        st.success(f"Live capture started on {interface} with filter '{capture_filter}'. Real-time alerting enabled.")
        st.session_state.packet_source_info = f"Live Capture on {interface} (Filter: {capture_filter})"
        # Rerun to update UI for capture status
        st.rerun()

    except Exception as e:
        st.session_state.is_capturing = False
        st.session_state.tshark_process = None
        st.error(f"Failed to start live capture: {e}")
        log_action("LIVE_CAPTURE_START_FAIL", {"interface": interface, "filter": capture_filter, "error": str(e)})
        return f"Failed to start live capture on {interface}."

def stop_live_capture(bpf_filter_for_processing=None):
    if not st.session_state.is_capturing:
        st.warning("No live capture is currently running.")
        return "No capture to stop."

    st.session_state.is_capturing = False
    log_action("LIVE_CAPTURE_STOP_INITIATED")

    # NEW: Stop pyshark capture and join the thread
    if st.session_state.tshark_process:
        try:
            st.session_state.tshark_process.close() # Close the capture
            # Ensure the thread finishes processing remaining packets if any
            if st.session_state.live_capture_thread and st.session_state.live_capture_thread.is_alive():
                st.session_state.live_capture_thread.join(timeout=5) # Wait for thread to finish
                if st.session_state.live_capture_thread.is_alive():
                    st.warning("Live capture thread did not terminate gracefully.")
        except Exception as e:
            st.error(f"Error stopping pyshark capture: {e}")
        st.session_state.tshark_process = None
        st.session_state.live_capture_thread = None
    
    # Process the collected pyshark packets using the existing tshark CLI pipeline
    if st.session_state.live_capture_pyshark_packets:
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tmp_pcap_file:
            temp_pcap_path = tmp_pcap_file.name
        
        try:
            # Reconstruct a pcap from pyshark packets - this needs to use scapy or similar
            # For simplicity, we'll write summaries directly.
            # A full implementation would involve writing actual packets to a pcap file.
            # For now, let's just log them and clear the live_capture_pyshark_packets
            
            # Convert pyshark packets to our internal raw_packet_data format for further processing
            st.session_state.raw_packet_data = []
            for i, pkt in enumerate(st.session_state.live_capture_pyshark_packets):
                # Try to get the raw JSON from pyshark, if available and well-formed
                pkt_json_str = pkt.json_src if hasattr(pkt, 'json_src') else json.dumps(pkt.to_dict())
                processed_pkt = _extract_packet_details_from_ek(pkt_json_str)
                if processed_pkt:
                    st.session_state.raw_packet_data.append(processed_pkt)
                else: # Fallback if pyshark.json_src is not reliable or doesn't exist
                    # Attempt a simpler conversion or just skip
                    simple_packet_dict = {
                        "summary": f"T:{pkt.sniff_time} Proto:{pkt.highest_layer}",
                        "details": {"layers": {}}
                    }
                    if hasattr(pkt, 'ip'):
                        simple_packet_dict["details"]["layers"]["ip"] = {"ip.src": pkt.ip.src, "ip.dst": pkt.ip.dst}
                    if hasattr(pkt, 'tcp'):
                        simple_packet_dict["details"]["layers"]["tcp"] = {"tcp.srcport": pkt.tcp.srcport, "tcp.dstport": pkt.tcp.dstport}
                    # ... add other common layers as needed for displaying summary
                    simple_packet_dict["details"]["layers"]["frame"] = {"frame.number": str(i + 1)}
                    st.session_state.raw_packet_data.append(simple_packet_dict)


            st.session_state.packet_source_info = f"Live Capture ({st.session_state.active_capture_interface}, Filter: '{st.session_state.active_capture_filter}')"
            # Since we've populated raw_packet_data from live_capture_pyshark_packets directly,
            # we don't need to call _process_pcap_file_with_tshark for *this* data source.
            # The summary stats and other analyses will now run on `st.session_state.raw_packet_data`.
            
            # Clean up temporary pcap file if it was used for actual file writing (currently not)
            if os.path.exists(temp_pcap_path):
                os.remove(temp_pcap_path)

        except Exception as e:
            st.error(f"Error processing captured packets after stop: {e}")
            log_action("LIVE_CAPTURE_POST_PROCESS_ERROR", {"error": str(e)})
        finally:
            st.session_state.live_capture_pyshark_packets = [] # Clear collected packets

    log_action("LIVE_CAPTURE_STOP_SUCCESS", {"packets_captured": st.session_state.packets_in_live_capture})
    st.success("Live capture stopped and packets processed.")
    return "Capture stopped & data processed."

def process_pcap_file(uploaded_file, bpf_filter=None): # Unchanged
    # ... (same as v1.6)
    return "Processed uploaded PCAP." # Abridged

def get_tshark_summary_stats(pcap_file_path, bpf_filter=None): # Unchanged
    # ... (same as v1.6)
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


# --- Threat Intelligence Functions (Unchanged from v1.6) ---
def is_public_ip(ip_address_str): # Unchanged
    # ... (same as v1.6)
    try:
        ip = ipaddress.ip_address(ip_address_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False
async def check_ip_abuseipdb(ip_address): # Unchanged
    # ... (same as v1.6)
    return None # Abridged
async def check_ip_geolocationio(ip_address): # Unchanged
    # ... (same as v1.6)
    return None # Abridged
async def run_threat_intelligence_checks(): # Unchanged
    # ... (same as v1.6 - orchestrates both API calls)
    pass # Abridged


# --- NEW: Packet Translation Function ---
async def translate_single_packet(packet_json_str, packet_index):
    """Calls the LLM to translate a single packet JSON."""
    log_action("PACKET_TRANSLATION_START", {"packet_index": packet_index})
    st.session_state.packet_translation_output = ""
    st.session_state.last_translated_packet_index = packet_index
    
    try:
        template_key = "packet_translation"
        # The prompt template already has the intro text.
        constructed_prompt = f"{PROMPT_TEMPLATES[template_key]}\n\n--- PACKET DATA ---\n{packet_json_str}"
        
        # Use Gemini by default for this task
        # We pass the single packet_json_str as the "list" for consistency with the function signature
        result = await call_gemini_api(constructed_prompt, packet_json_str, template_key, "translate this packet")
        
        st.session_state.packet_translation_output = result.get("text", "Translation failed.")
        log_action("PACKET_TRANSLATION_SUCCESS", {"packet_index": packet_index, "translation": result.get("text", "")})
    
    except Exception as e:
        st.session_state.packet_translation_output = f"Error during translation: {e}"
        log_action("PACKET_TRANSLATION_ERROR", {"packet_index": packet_index, "error": str(e)})


# --- Streamlit App UI ---
st.set_page_config(page_title=APP_TITLE, layout="wide")
if 'db_initialized' not in st.session_state: init_db(); st.session_state.db_initialized = True; log_action("APP_START")
st.title(f"{APP_TITLE} - Network Traffic Analysis with AI")

# Initialize session state (ensure all from v1.6 are present)
if 'is_capturing' not in st.session_state: st.session_state.is_capturing = False
if 'raw_packet_data' not in st.session_state: st.session_state.raw_packet_data = []
if 'captured_packets_log' not in st.session_state: st.session_state.captured_packets_log = []
if 'llm_analysis_results' not in st.session_state: st.session_state.llm_analysis_results = []
if 'alerts' not in st.session_state: st.session_state.alerts = []
if 'current_report_content' not in st.session_state: st.session_state.current_report_content = ""
if 'packet_source_info' not in st.session_state: st.session_state.packet_source_info = "N/A"
if 'tshark_process' not in st.session_state: st.session_state.tshark_process = None
if 'temp_capture_file' not in st.session_state: st.session_state.temp_capture_file = None
if 'temp_capture_file_for_processing' not in st.session_state: st.session_state.temp_capture_file_for_processing = None
if 'last_processed_pcap_path' not in st.session_state: st.session_state.last_processed_pcap_path = None
if 'selected_packet_index' not in st.session_state: st.session_state.selected_packet_index = None
if 'current_prompt_template' not in st.session_state: st.session_state.current_prompt_template = "general_analysis"
if 'nlp_suggested_filter' not in st.session_state: st.session_state.nlp_suggested_filter = ""
if 'nlp_interpretation_notes' not in st.session_state: st.session_state.nlp_interpretation_notes = ""
if 'nlp_extracted_entities' not in st.session_state: st.session_state.nlp_extracted_entities = {}
if 'nlp_suggested_tshark_fields' not in st.session_state: st.session_state.nlp_suggested_tshark_fields = []
if 'field_extraction_df' not in st.session_state: st.session_state.field_extraction_df = None
if 'nlp_command_history' not in st.session_state: st.session_state.nlp_command_history = deque(maxlen=NLP_HISTORY_LENGTH)
if 'current_pcap_session_id' not in st.session_state: st.session_state.current_pcap_session_id = None
if 'pcap_save_dir' not in st.session_state: st.session_state.pcap_save_dir = os.getcwd()
if 'manual_capture_filter_value' not in st.session_state: st.session_state.manual_capture_filter_value = ""
if 'active_capture_filter' not in st.session_state: st.session_state.active_capture_filter = ""
if 'usr_q_add_in' not in st.session_state: st.session_state.usr_q_add_in = ""
if 'num_pkts_llm_in' not in st.session_state: st.session_state.num_pkts_llm_in = 10
if 'current_report_format' not in st.session_state: st.session_state.current_report_format = "Markdown"
if 'tshark_summary_stats' not in st.session_state: st.session_state.tshark_summary_stats = None
if 'pcap_processing_filter' not in st.session_state: st.session_state.pcap_processing_filter = ""
if 'abuseipdb_cache' not in st.session_state: st.session_state.abuseipdb_cache = {}
if 'ip_threat_intel_results' not in st.session_state: st.session_state.ip_threat_intel_results = {}
if 'ip_threat_intel_summary_message' not in st.session_state: st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
if 'abuseipdb_rate_limited_until' not in st.session_state: st.session_state.abuseipdb_rate_limited_until = None
if 'ipgeolocation_cache' not in st.session_state: st.session_state.ipgeolocation_cache = {}
if 'ip_geolocation_results' not in st.session_state: st.session_state.ip_geolocation_results = {}
if 'ipgeolocation_rate_limited_until' not in st.session_state: st.session_state.ipgeolocation_rate_limited_until = None
if 'packet_translation_output' not in st.session_state: st.session_state.packet_translation_output = ""
if 'last_translated_packet_index' not in st.session_state: st.session_state.last_translated_packet_index = None

# NEW: State for live capture thread and packet count
if 'live_capture_thread' not in st.session_state: st.session_state.live_capture_thread = None
if 'packets_in_live_capture' not in st.session_state: st.session_state.packets_in_live_capture = 0
if 'active_capture_interface' not in st.session_state: st.session_state.active_capture_interface = ""
if 'live_capture_pyshark_packets' not in st.session_state: st.session_state.live_capture_pyshark_packets = []

# NEW: LLM Rate limit tracking
if 'gemini_rate_limited_until' not in st.session_state: st.session_state.gemini_rate_limited_until = None
if 'mistral_rate_limited_until' not in st.session_state: st.session_state.mistral_rate_limited_until = None
if 'groq_rate_limited_until' not in st.session_state: st.session_state.groq_rate_limited_until = None


async def main_ui():
    with st.sidebar:
        st.header("⚙️ Controls & Configuration")
        # Display live capture status if active
        if st.session_state.is_capturing:
            st.info(f"⚡ Live Capturing: {st.session_state.packets_in_live_capture} packets captured.")
            st.warning("While live capture is running, most other functions are disabled.")
            
        st.subheader("🚨 Alert Overview") # ...
        if st.session_state.alerts:
            # Sort alerts by severity (High, Medium, Low) and then by timestamp
            severity_order = {"High": 3, "Medium": 2, "Low": 1}
            sorted_alerts = sorted(
                st.session_state.alerts,
                key=lambda x: (severity_order.get(x["severity"], 0), x["timestamp"]),
                reverse=True
            )
            for alert in sorted_alerts:
                color = "red" if alert["severity"] == "High" else "orange" if alert["severity"] == "Medium" else "blue"
                st.markdown(f"<p style='color:{color};'><b>{alert['severity']} Alert:</b> {alert['message']}</p>", unsafe_allow_html=True)
        else:
            st.caption("No alerts yet.")
        st.markdown("---")

        # API Key Checks for all services
        if not GEMINI_API_KEY: st.caption("⚠️ Gemini AI limited (API key N/A).")
        if not MISTRAL_API_KEY: st.caption("⚠️ Mistral AI limited (API key N/A).")
        if not GROQ_API_KEY: st.caption("⚠️ Groq AI limited (API key N/A).")
        if not ABUSEIPDB_API_KEY: st.caption("⚠️ AbuseIPDB Threat Intel limited (API key N/A).")
        if not IPGEOLOCATION_API_KEY: st.caption("⚠️ IP Geolocation limited (API key N/A).")
        
        # NEW: Display LLM Rate Limit Status
        if st.session_state.get('gemini_rate_limited_until') and datetime.now() < st.session_state.gemini_rate_limited_until:
            st.caption(f"⏳ Gemini is rate-limited until {st.session_state.gemini_rate_limited_until.strftime('%H:%M:%S')}.")
        if st.session_state.get('mistral_rate_limited_until') and datetime.now() < st.session_state.mistral_rate_limited_until:
            st.caption(f"⏳ Mistral AI is rate-limited until {st.session_state.mistral_rate_limited_until.strftime('%H:%M:%S')}.")
        if st.session_state.get('groq_rate_limited_until') and datetime.now() < st.session_state.groq_rate_limited_until:
            st.caption(f"⏳ Groq AI is rate-limited until {st.session_state.groq_rate_limited_until.strftime('%H:%M:%S')}.")


        st.markdown("---") # ... (PCAP Storage, NLP, etc. from v1.6)

        st.subheader("📦 Packet Source")
        source_option = st.radio("Packet Source:", ("Live Capture", "Upload PCAP"), key="src_opt_radio_ti", disabled=st.session_state.is_capturing)
        
        # Interface selection only visible for live capture
        interfaces = ["None"]
        try:
            interfaces_raw = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True).stdout
            interfaces.extend([line.split(' ')[1] for line in interfaces_raw.splitlines() if ' ' in line and not line.startswith('(')])
        except Exception:
            st.error("tshark not found or error listing interfaces. Please ensure tshark is installed and in PATH.")
        
        selected_interface = st.selectbox("Select Interface for Live Capture:", interfaces, key="live_interface_ti", disabled=st.session_state.is_capturing)
        
        active_capture_filter_for_live = st.text_input("BPF Filter for Live Capture (optional):", value=st.session_state.manual_capture_filter_value, key="manual_capture_filter_input_ti", disabled=st.session_state.is_capturing)
        st.session_state.manual_capture_filter_value = active_capture_filter_for_live


        if source_option == "Live Capture":
            col_live_cap_start, col_live_cap_stop = st.columns(2)
            with col_live_cap_start:
                if st.button("🚀 Start Live Capture", key="start_cap_ti", disabled=st.session_state.is_capturing or selected_interface == "None"):
                    if selected_interface == "None":
                        st.error("Please select a network interface to start live capture.")
                    else:
                        start_live_capture(selected_interface, active_capture_filter_for_live)
                        # No st.rerun here as start_live_capture already does it
            with col_live_cap_stop:
                if st.button("🛑 Stop Live Capture", key="stop_cap_ti", disabled=not st.session_state.is_capturing):
                    with st.spinner("Stopping capture and processing..."):
                        stop_live_capture(bpf_filter_for_processing=active_capture_filter_for_live)
                    # Automatically run threat intel checks after stopping live capture and processing
                    if st.session_state.raw_packet_data:
                        with st.spinner("Running threat intelligence checks..."):
                            await run_threat_intelligence_checks()
                    st.rerun() # To update the display with TI results/alerts

        elif source_option == "Upload PCAP":
            uploaded_file = st.file_uploader("Upload PCAP/NG", type=["pcap","pcapng","cap"], key="pcap_up_ti", disabled=st.session_state.is_capturing)
            st.session_state.pcap_processing_filter = st.text_input("BPF Filter for this PCAP (optional):", value=st.session_state.get("pcap_processing_filter",""), key="pcap_proc_filter_input_ti", disabled=st.session_state.is_capturing)
            if uploaded_file and st.button("📄 Process PCAP File", key="proc_pcap_ti", disabled=st.session_state.is_capturing):
                with st.spinner(f"Processing {uploaded_file.name}..."):
                    st.session_state.raw_packet_data = [] # Clear previous data
                    st.session_state.captured_packets_log = []
                    st.session_state.llm_analysis_results = []
                    st.session_state.alerts = []
                    st.session_state.tshark_summary_stats = None
                    st.session_state.ip_threat_intel_results = {}
                    st.session_state.ip_geolocation_results = {}
                    st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
                    st.session_state.packet_translation_output = "" # Clear translation
                    st.session_state.last_translated_packet_index = None

                    status = process_pcap_file(uploaded_file, bpf_filter=st.session_state.pcap_processing_filter)
                    st.success(status)
                # Automatically run threat intel checks after processing PCAP
                if st.session_state.raw_packet_data:
                    with st.spinner("Running threat intelligence checks..."):
                        await run_threat_intelligence_checks()
                    st.rerun()
        
        # Manual Threat Intel Check Button (could be useful if auto-run is disabled or for re-checks)
        if st.session_state.raw_packet_data and not st.session_state.is_capturing:
            st.markdown("---")
            st.subheader("🛡️ Threat Intelligence")
            if st.button("Run/Refresh IP Threat Intel Checks", key="manual_ti_check_btn"):
                with st.spinner("Running threat intelligence checks..."):
                    await run_threat_intelligence_checks()
                st.rerun()
        
        st.markdown("---")
        st.subheader("🧠 LLM Analysis") # ... (LLM Analysis section from v1.6)
        st.subheader("📄 Reporting") # ... (Reporting section from v1.6)
        st.markdown("---"); st.caption(f"Circuit Shark v1.7 (Real-time Alerting)")


    # --- Main Area for Display ---
    # Display tshark -z Summary Stats (if generated)
    if st.session_state.get("tshark_summary_stats") and not st.session_state.is_capturing: # Only show if not live capturing
        st.header("📈 tshark Summary Statistics") # ...
        st.markdown("---")
    
    # Display Traffic Analysis Dashboard (if data exists)
    if st.session_state.get("raw_packet_data") and not st.session_state.is_capturing: # Only show if not live capturing
        st.header("📊 Traffic Analysis Dashboard") # ...
        st.markdown("---")

    # Display Quick Field Extraction Results (if generated)
    if st.session_state.field_extraction_df is not None and not st.session_state.field_extraction_df.empty and not st.session_state.is_capturing: # Only show if not live capturing
        st.subheader("🔬 Quick Field Extraction Results"); st.dataframe(st.session_state.field_extraction_df) # ...
        st.markdown("---")

    # Main content columns for Packet Log, LLM Analysis & Alerts
    col1_main, col2_main = st.columns([2,3]) 
    with col1_main: 
        st.header("📦 Packet Data Log")
        
        # Display list of captured packets for selection (if not live capturing)
        if st.session_state.raw_packet_data and not st.session_state.is_capturing:
            packet_summaries_for_display = [f"Pkt {i+1}: {pkt['summary']}" for i, pkt in enumerate(st.session_state.raw_packet_data)]
            selected_summary = st.selectbox("Select a packet to view details:", [""] + packet_summaries_for_display, key="pkt_select")
            if selected_summary:
                st.session_state.selected_packet_index = packet_summaries_for_display.index(selected_summary)
            else:
                st.session_state.selected_packet_index = None
        elif st.session_state.is_capturing:
            st.info(f"Live capture running. Packets: {st.session_state.packets_in_live_capture}. Packet log disabled during capture.")
        else:
            st.info("Upload a PCAP or start a live capture to see packet data.")


        if st.session_state.selected_packet_index is not None and not st.session_state.is_capturing: # Display Packet JSON and Threat Intel
            st.subheader(f"Pkt {st.session_state.selected_packet_index + 1} Details")
            try:
                idx = st.session_state.selected_packet_index
                selected_pkt_details = st.session_state.raw_packet_data[idx]["details"]
                
                # Display JSON
                st.json(selected_pkt_details, expanded=False)

                # Display Threat Intel
                packet_ips_to_show_intel = set()
                layers = selected_pkt_details.get("layers", {})
                if "ip" in layers:
                    if layers["ip"].get("ip.src"): packet_ips_to_show_intel.add(layers["ip"]["ip.src"])
                    if layers["ip"].get("ip.dst"): packet_ips_to_show_intel.add(layers["ip"]["ip.dst"])
                elif "ipv6" in layers:
                    if layers["ipv6"].get("ipv6.src"): packet_ips_to_show_intel.add(layers["ipv6"]["ipv6.src"])
                    if layers["ipv6"].get("ipv6.dst"): packet_ips_to_show_intel.add(layers["ipv6"]["ipv6.dst"])
                
                shown_intel_header = False
                for ip_addr in packet_ips_to_show_intel:
                    has_abuse_intel = ip_addr in st.session_state.ip_threat_intel_results
                    has_geo_intel = ip_addr in st.session_state.ip_geolocation_results
                    
                    if has_abuse_intel or has_geo_intel:
                        if not shown_intel_header:
                            st.markdown("---")
                            st.subheader("Threat Intelligence for IPs in this Packet:")
                            shown_intel_header = True
                        
                        # AbuseIPDB Intel
                        if has_abuse_intel:
                            intel = st.session_state.ip_threat_intel_results[ip_addr]
                            score = intel.get('abuseConfidenceScore', 0)
                            color = "green"
                            if score >= 75: color = "red"
                            elif score >= 50: color = "orange"
                            elif score > 0: color = "blue"
                            
                            with st.expander(f"🛡️ AbuseIPDB Intel for {ip_addr} (Score: {score}%)", expanded=False):
                                st.markdown(f"<p style='color:{color};'>**Abuse Score: {score}%** (Reports: {intel.get('totalReports',0)})</p>", unsafe_allow_html=True)
                                st.write(f"Country: {intel.get('countryCode','N/A')}, ISP: {intel.get('isp','N/A')}")
                                st.write(f"Usage Type: {intel.get('usageType','N/A')}, Domain: {intel.get('domain','N/A')}")
                                st.write(f"Last Reported: {intel.get('lastReportedAt','N/A')}")
                                if intel.get("notes"): st.caption(intel.get("notes"))
                        
                        # Geolocation Intel
                        if has_geo_intel:
                            intel_geo = st.session_state.ip_geolocation_results[ip_addr]
                            country = intel_geo.get('country_name', 'N/A')
                            is_tor = intel_geo.get('is_tor', False)
                            tor_color = "red" if is_tor else "green"
                            tor_text = "Yes" if is_tor else "No"
                            
                            with st.expander(f"🌍 Geolocation Intel for {ip_addr} ({country})", expanded=False):
                                st.write(f"**Country:** {country}, **City:** {intel_geo.get('city','N/A')}")
                                st.write(f"**ISP:** {intel_geo.get('isp','N/A')}")
                                st.write(f"**Organization:** {intel_geo.get('organization','N/A')}")
                                st.markdown(f"**TOR Node:** <span style='color:{tor_color}; font-weight:bold;'>{tor_text}</span>", unsafe_allow_html=True)

                # Packet Translation Button & Display
                st.markdown("---") # Separator
                if st.button("🧠 Translate this packet with AI", key=f"translate_btn_{idx}"):
                    with st.spinner(f"Translating Packet {idx + 1}..."):
                        packet_json_str = json.dumps(selected_pkt_details)
                        # We can await here because main_ui() is async
                        await translate_single_packet(packet_json_str, idx) 
                        st.rerun() # Rerun to show the output

                # Display the translation if it exists for this packet
                if st.session_state.packet_translation_output and st.session_state.get('last_translated_packet_index') == idx:
                    st.subheader("🤖 AI Packet Translation")
                    st.markdown(st.session_state.packet_translation_output)

            except IndexError:
                st.error("Could not retrieve packet details."); st.session_state.selected_packet_index = None
            except Exception as e:
                st.error(f"Error displaying packet details/intel: {e}")

            if st.button("Close Details", key="close_pkt_det_main_dash_btn_ti"): 
                st.session_state.selected_packet_index = None
                st.session_state.packet_translation_output = "" # Clear translation on close
                st.session_state.last_translated_packet_index = None
                st.rerun()
            
    with col2_main: 
        st.header("💡 LLM Analysis & Alerts")
        # Display Threat Intel Summary Message
        if st.session_state.get("ip_threat_intel_summary_message"):
            st.info(st.session_state.ip_threat_intel_summary_message)
            st.markdown("---")

        if st.session_state.alerts: # Alert display 
            st.subheader("🚨 Alerts!")
            # Sort alerts by severity (High, Medium, Low) and then by timestamp
            severity_order = {"High": 3, "Medium": 2, "Low": 1}
            sorted_alerts = sorted(
                st.session_state.alerts,
                key=lambda x: (severity_order.get(x["severity"], 0), x["timestamp"]),
                reverse=True
            )
            for alert in sorted_alerts:
                color = "red" if alert["severity"] == "High" else "orange" if alert["severity"] == "Medium" else "blue"
                st.markdown(f"<p style='color:{color};'><b>{alert['severity']} Alert:</b> {alert['message']}</p>", unsafe_allow_html=True)
        else:
            st.caption("No alerts yet.")

        if st.session_state.llm_analysis_results: # LLM insights display
            st.subheader("LLM Insights:") 
            for result in st.session_state.llm_analysis_results:
                st.markdown(f"**Analysis from {result['llm_name']} ({result['template_key']}):**")
                st.markdown(result["response_text"])
                if result["alerts"]:
                    for alert in result["alerts"]:
                        color = "red" if alert["severity"] == "High" else "orange" if alert["severity"] == "Medium" else "blue"
                        st.markdown(f"<p style='color:{color};'><b>LLM ALERT ({alert['severity']}):</b> {alert['message']}</p>", unsafe_allow_html=True)
                st.markdown("---")
    
    st.markdown("---"); st.header("📋 Generated Report Preview") # Report Preview 
    if st.session_state.current_report_content:
        # Check format and render accordingly
        if st.session_state.current_report_format == "Markdown":
            st.markdown(st.session_state.current_report_content)
        elif st.session_state.current_report_format == "HTML":
            st.components.v1.html(st.session_state.current_report_content, height=400, scrolling=True)
        elif st.session_state.current_report_format == "PDF":
            st.info("PDF reports are generated on demand and downloaded. Preview not available.")
    else:
        st.info("Generate an LLM analysis or report to see a preview here.")
    st.markdown("---"); st.markdown(f"""<div style="text-align: center; font-size: small;"><p><strong>Disclaimer:</strong> Conceptual. LLM outputs require expert verification.</p></div>""", unsafe_allow_html=True)


if __name__ == "__main__":
    # Initialize all session state keys
    for key, default_value in { 
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
        'abuseipdb_cache': {}, 
        'ip_threat_intel_results': {}, 
        'ip_threat_intel_summary_message': "Threat intelligence checks not yet run.", 
        'abuseipdb_rate_limited_until': None, 
        'ipgeolocation_cache': {},
        'ip_geolocation_results': {},
        'ipgeolocation_rate_limited_until': None,
        'packet_translation_output': "",
        'last_translated_packet_index': None,
        # NEW: State for live capture thread and packet count
        'live_capture_thread': None,
        'packets_in_live_capture': 0,
        'active_capture_interface': "",
        'live_capture_pyshark_packets': [],
        # NEW: LLM Rate limit tracking
        'gemini_rate_limited_until': None,
        'mistral_rate_limited_until': None,
        'groq_rate_limited_until': None
    }.items():
        if key not in st.session_state:
            st.session_state[key] = default_value
    
    st.run_async(main_ui())
```