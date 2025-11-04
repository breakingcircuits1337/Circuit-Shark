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
import pyshark # For real-time packet capture
import threading # For running pyshark in a separate thread

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

# Rate limiting delays for LLMs
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

# --- Prompt Templates ---
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

# --- Database Setup and Helper Functions ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action_type TEXT NOT NULL,
            details TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pcap_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            original_source TEXT NOT NULL,
            filepath TEXT,
            filter_used TEXT,
            notes TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS llm_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pcap_session_id INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            llm_name TEXT,
            template_key TEXT,
            query_addon TEXT,
            response_text TEXT,
            alerts_json TEXT,
            FOREIGN KEY (pcap_session_id) REFERENCES pcap_sessions(id)
        )
    """)
    conn.commit()
    conn.close()

def log_action(action_type, details_dict=None):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        details_json = json.dumps(details_dict) if details_dict else "{}"
        cursor.execute("INSERT INTO audit_log (action_type, details) VALUES (?, ?)", (action_type, details_json))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        st.caption(f"DB Log Err (Action): {e}")

def get_recent_actions_summary(limit=NLP_HISTORY_LENGTH):
    summary_lines = []
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, action_type, details FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        for row in rows:
            ts, action, details_str = row
            details = json.loads(details_str)
            summary_lines.append(f"- {ts} [{action}]: {details.get('command', details.get('source', details.get('llm', '')))}")
        conn.close()
    except sqlite3.Error as e:
        st.caption(f"DB Log Err (Summary): {e}")
    return "\n".join(summary_lines)

def log_pcap_session(original_source_info, saved_filepath, filter_used, notes=""):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO pcap_sessions (original_source, filepath, filter_used, notes) VALUES (?, ?, ?, ?)",
                       (original_source_info, saved_filepath, filter_used, notes))
        pcap_session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        log_action("SAVE_PCAP_SESSION_SUCCESS", {"saved_filepath": saved_filepath, "source": original_source_info, "notes": notes})
        return pcap_session_id
    except sqlite3.Error as e:
        st.error(f"DB Err saving PCAP: {e}")
        return None

def log_llm_analysis(pcap_session_id, llm_name, template_key, query_addon, response_text, alerts_list):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        alerts_json = json.dumps(alerts_list)
        cursor.execute("INSERT INTO llm_analyses (pcap_session_id, llm_name, template_key, query_addon, response_text, alerts_json) VALUES (?, ?, ?, ?, ?, ?)",
                       (pcap_session_id, llm_name, template_key, query_addon, response_text, alerts_json))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        st.caption(f"DB Log Err (LLM Analysis): {e}")

# --- NLP Command Parsing LLM Call ---
async def interpret_command_with_llm(user_command, command_history_str=""):
    log_action("NLP_COMMAND_INTERPRET_START", {"command": user_command})
    if not GEMINI_API_KEY:
        return {"interpretation_notes": "NLP LLM (Gemini) not configured."}

    prompt = (
        "You are an intelligent network analysis assistant. The user will provide a command or question related to network packet analysis. "
        "Your task is to interpret this command and extract key parameters for a network packet analysis tool. "
        "Specifically, identify the 'command_type', 'bpf_filter' (BPF syntax), 'llm_analysis_focus' (from general_analysis, dns_focus, http_vulnerability_check, tls_analysis, malware_communication_hunt), 'llm_query_addon', and 'tshark_fields_to_extract' (comma-separated tshark field names like 'ip.src,tcp.port'). "
        "If no specific command type is clear, default to 'analytical_query'. If no filter is specified, return an empty string for bpf_filter. "
        "If the user asks for a specific analysis, set llm_analysis_focus accordingly. If a question is posed for the LLM, put it in llm_query_addon. "
        "If specific fields are requested for extraction, list them in tshark_fields_to_extract.\n\n"
        "Here's the history of recent commands for context:\n"
        f"{command_history_str}\n\n"
        "User Command: {user_command}\n\n"
        "Provide your interpretation in JSON format with the following keys:\n"
        "{ \"command_type\": \"<type>\", \"bpf_filter\": \"<filter>\", \"llm_analysis_focus\": \"<focus>\", \"llm_query_addon\": \"<query>\", \"tshark_fields_to_extract\": \"<fields>\", \"interpretation_notes\": \"<notes>\" }"
    ).format(user_command=user_command)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY
            }
            data = {
                "contents": [
                    {"role": "user", "parts": [{"text": prompt}]}
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "topK": 1,
                    "topP": 1,
                    "maxOutputTokens": 500,
                }
            }
            response = await client.post(GEMINI_API_URL, headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            # Extract text from the LLM's response
            text_response = response_json.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '').strip()
            
            # Attempt to parse the JSON string from the LLM's text response
            try:
                parsed_command = json.loads(text_response)
                log_action("NLP_COMMAND_INTERPRET_SUCCESS", {"command": user_command, "interpretation": parsed_command})
                return parsed_command
            except json.JSONDecodeError:
                st.warning(f"LLM did not return valid JSON for command interpretation. Raw response: {text_response[:200]}")
                return {"interpretation_notes": "LLM response malformed.", "command_type": "analytical_query"}

    except httpx.HTTPStatusError as e:
        st.error(f"LLM API Error during command interpretation: {e.response.status_code} - {e.response.text[:100]}")
        log_action("NLP_COMMAND_INTERPRET_ERROR", {"command": user_command, "error": f"HTTP {e.response.status_code}"})
    except httpx.RequestError as e:
        st.error(f"Network Error during command interpretation: {e}")
        log_action("NLP_COMMAND_INTERPRET_ERROR", {"command": user_command, "error": f"Network Error: {e}"})
    except Exception as e:
        st.error(f"Unexpected Error during command interpretation: {e}")
        log_action("NLP_COMMAND_INTERPRET_ERROR", {"command": user_command, "error": str(e)})
    return {"command_type": "analytical_query", "interpretation_notes": "Interpretation failed."}

# --- Function to run tshark for field extraction ---
def run_tshark_field_extraction(fields_to_extract, bpf_filter, pcap_file_path=None):
    if not pcap_file_path or not os.path.exists(pcap_file_path):
        st.warning("No PCAP file available for field extraction.")
        return pd.DataFrame()

    if not fields_to_extract:
        st.warning("No fields specified for extraction.")
        return pd.DataFrame()

    fields_args = []
    for field in fields_to_extract:
        fields_args.extend(['-e', field.strip()])

    tshark_command = [TSHARK_CMD, '-r', pcap_file_path, '-Tfields']
    tshark_command.extend(fields_args)
    if bpf_filter:
        tshark_command.extend(['-Y', bpf_filter])

    log_action("TSHARK_FIELD_EXTRACTION_START", {"pcap_path": pcap_file_path, "filter": bpf_filter, "fields": fields_to_extract})

    try:
        process = subprocess.run(tshark_command, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace')
        output_lines = process.stdout.strip().split('\n')
        
        data = []
        if output_lines and output_lines[0]: # Ensure output is not empty
            for line in output_lines:
                data.append(line.split('\t')) # tshark -Tfields uses tabs by default

            df = pd.DataFrame(data, columns=fields_to_extract)
            log_action("TSHARK_FIELD_EXTRACTION_SUCCESS", {"num_rows": len(df), "fields": fields_to_extract})
            return df
        else:
            st.info("No data extracted for the specified fields and filter.")
            log_action("TSHARK_FIELD_EXTRACTION_NO_DATA", {"pcap_path": pcap_file_path, "filter": bpf_filter, "fields": fields_to_extract})
            return pd.DataFrame()

    except FileNotFoundError:
        st.error(f"{TSHARK_CMD} command not found. Please ensure Wireshark/tshark is installed and in your PATH.")
        log_action("TSHARK_NOT_FOUND")
    except subprocess.CalledProcessError as e:
        st.error(f"Tshark error: {e.stderr}")
        log_action("TSHARK_FIELD_EXTRACTION_ERROR", {"error": e.stderr})
    except Exception as e:
        st.error(f"An unexpected error occurred during tshark field extraction: {e}")
        log_action("TSHARK_FIELD_EXTRACTION_ERROR", {"error": str(e)})
    return pd.DataFrame()


# --- Main LLM API Call Functions ---
def parse_alerts_from_llm_text(llm_text, source_llm="LLM"):
    alerts = []
    alert_pattern = re.compile(r"ALERT:\s*\[Severity:\s*(High|Medium|Low)\]\s*-\s*(.*?)(?:\s*-\s*\[?(Packet number|IP address)?:\s*([^\]]+)\]?)?", re.IGNORECASE)
    
    for line in llm_text.splitlines():
        match = alert_pattern.match(line.strip())
        if match:
            severity = match.group(1).capitalize()
            description = match.group(2).strip()
            context_type = match.group(3)
            context_value = match.group(4)
            
            message = description
            if context_type and context_value:
                message += f" (Context: {context_value})"
            
            alerts.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": source_llm,
                "message": message,
                "severity": severity
            })
    return alerts

async def call_gemini_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon):
    if st.session_state.get("gemini_rate_limited_until") and datetime.now() < st.session_state.gemini_rate_limited_until:
        log_action("LLM_RATE_LIMIT_BLOCKED", {"llm": "Gemini"})
        return {'text': f'Gemini API is rate-limited until {st.session_state.gemini_rate_limited_until.strftime("%H:%M:%S")}. Please wait.', 'alerts': []}
    
    if not GEMINI_API_KEY:
        return {"text": "Gemini API Key not configured.", "alerts": []}

    full_prompt = f"{constructed_prompt}\n\n--- PACKET DATA ---\n{packet_data_json_list_str}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY
            }
            data = {
                "contents": [
                    {"role": "user", "parts": [{"text": full_prompt}]}
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "topK": 1,
                    "topP": 1,
                    "maxOutputTokens": 2000,
                }
            }
            response = await client.post(GEMINI_API_URL, headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            # Extract text from the LLM's response
            text_response = response_json.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '').strip()
            
            alerts = parse_alerts_from_llm_text(text_response, source_llm="Google Gemini")
            log_action("LLM_CALL_SUCCESS", {"llm": "Gemini", "template": template_key, "query_addon": query_addon, "alerts_count": len(alerts)})
            return {"text": text_response, "alerts": alerts}

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            st.session_state.gemini_rate_limited_until = datetime.now() + timedelta(minutes=GEMINI_RATE_LIMIT_DELAY_MINUTES)
            log_action("LLM_RATE_LIMIT_HIT", {"llm": "Gemini", "status_code": 429})
            return {"text": f"Gemini API rate limit hit. Try again after {GEMINI_RATE_LIMIT_DELAY_MINUTES} minutes.", "alerts": []}
        st.error(f"Gemini API Error: {e.response.status_code} - {e.response.text[:100]}")
        log_action("LLM_CALL_ERROR", {"llm": "Gemini", "error": f"HTTP {e.response.status_code}"})
    except httpx.RequestError as e:
        st.error(f"Network Error calling Gemini API: {e}")
        log_action("LLM_CALL_ERROR", {"llm": "Gemini", "error": f"Network Error: {e}"})
    except Exception as e:
        st.error(f"Unexpected Error calling Gemini API: {e}")
        log_action("LLM_CALL_ERROR", {"llm": "Gemini", "error": str(e)})
    return {"text": "Error communicating with Gemini API.", "alerts": []}

async def call_mistral_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon):
    if st.session_state.get("mistral_rate_limited_until") and datetime.now() < st.session_state.mistral_rate_limited_until:
        log_action("LLM_RATE_LIMIT_BLOCKED", {"llm": "Mistral"})
        return {'text': f'Mistral API is rate-limited until {st.session_state.mistral_rate_limited_until.strftime("%H:%M:%S")}. Please wait.', 'alerts': []}

    if not MISTRAL_API_KEY:
        return {"text": "Mistral AI API Key not configured.", "alerts": []}

    full_prompt = f"{constructed_prompt}\n\n--- PACKET DATA ---\n{packet_data_json_list_str}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {MISTRAL_API_KEY}"
            }
            data = {
                "model": MISTRAL_DEFAULT_MODEL,
                "messages": [{"role": "user", "content": full_prompt}],
                "temperature": 0.2,
                "max_tokens": 2000,
            }
            response = await client.post(MISTRAL_API_URL, headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            text_response = response_json.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
            
            alerts = parse_alerts_from_llm_text(text_response, source_llm="Mistral AI")
            log_action("LLM_CALL_SUCCESS", {"llm": "Mistral", "template": template_key, "query_addon": query_addon, "alerts_count": len(alerts)})
            return {"text": text_response, "alerts": alerts}

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            st.session_state.mistral_rate_limited_until = datetime.now() + timedelta(minutes=MISTRAL_RATE_LIMIT_DELAY_MINUTES)
            log_action("LLM_RATE_LIMIT_HIT", {"llm": "Mistral", "status_code": 429})
            return {"text": f"Mistral API rate limit hit. Try again after {MISTRAL_RATE_LIMIT_DELAY_MINUTES} minutes.", "alerts": []}
        st.error(f"Mistral AI API Error: {e.response.status_code} - {e.response.text[:100]}")
        log_action("LLM_CALL_ERROR", {"llm": "Mistral", "error": f"HTTP {e.response.status_code}"})
    except httpx.RequestError as e:
        st.error(f"Network Error calling Mistral AI API: {e}")
        log_action("LLM_CALL_ERROR", {"llm": "Mistral", "error": f"Network Error: {e}"})
    except Exception as e:
        st.error(f"Unexpected Error calling Mistral AI API: {e}")
        log_action("LLM_CALL_ERROR", {"llm": "Mistral", "error": str(e)})
    return {"text": "Error communicating with Mistral AI API.", "alerts": []}

async def call_groq_api(constructed_prompt, packet_data_json_list_str, template_key, query_addon):
    if st.session_state.get("groq_rate_limited_until") and datetime.now() < st.session_state.groq_rate_limited_until:
        log_action("LLM_RATE_LIMIT_BLOCKED", {"llm": "Groq"})
        return {'text': f'Groq API is rate-limited until {st.session_state.groq_rate_limited_until.strftime("%H:%M:%S")}. Please wait.', 'alerts': []}

    if not GROQ_API_KEY:
        return {"text": "Groq API Key not configured.", "alerts": []}

    full_prompt = f"{constructed_prompt}\n\n--- PACKET DATA ---\n{packet_data_json_list_str}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}"
            }
            data = {
                "model": GROQ_DEFAULT_MODEL,
                "messages": [{"role": "user", "content": full_prompt}],
                "temperature": 0.2,
                "max_tokens": 2000,
            }
            response = await client.post(GROQ_API_URL, headers=headers, json=data)
            response.raise_for_status()
            response_json = response.json()
            
            text_response = response_json.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
            
            alerts = parse_alerts_from_llm_text(text_response, source_llm="Groq")
            log_action("LLM_CALL_SUCCESS", {"llm": "Groq", "template": template_key, "query_addon": query_addon, "alerts_count": len(alerts)})
            return {"text": text_response, "alerts": alerts}

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            st.session_state.groq_rate_limited_until = datetime.now() + timedelta(minutes=GROQ_RATE_LIMIT_DELAY_MINUTES)
            log_action("LLM_RATE_LIMIT_HIT", {"llm": "Groq", "status_code": 429})
            return {"text": f"Groq API rate limit hit. Try again after {GROQ_RATE_LIMIT_DELAY_MINUTES} minutes.", "alerts": []}
        st.error(f"Groq API Error: {e.response.status_code} - {e.response.text[:100]}")
        log_action("LLM_CALL_ERROR", {"llm": "Groq", "error": f"HTTP {e.response.status_code}"})
    except httpx.RequestError as e:
        st.error(f"Network Error calling Groq API: {e}")
        log_action("LLM_CALL_ERROR", {"llm": "Groq", "error": f"Network Error: {e}"})
    except Exception as e:
        st.error(f"Unexpected Error calling Groq API: {e}")
        log_action("LLM_CALL_ERROR", {"llm": "Groq", "error": str(e)})
    return {"text": "Error communicating with Groq API.", "alerts": []}

# --- Predefined Rules Engine ---
PREDEFINED_RULES = [
    {"name": "Telnet Traffic Detected", "description": "Detects Telnet traffic (TCP port 23). Telnet is insecure.", "severity": "High", "conditions": lambda pkt_layers: "tcp" in pkt_layers and pkt_layers["tcp"].get("tcp.port") == "23"},
    {"name": "FTP Control Traffic Detected", "description": "Detects FTP control traffic (TCP port 21). Credentials may be in plaintext.", "severity": "Medium", "conditions": lambda pkt_layers: "tcp" in pkt_layers and pkt_layers["tcp"].get("tcp.port") == "21"},
    {"name": "Unencrypted HTTP Login", "description": "Detects HTTP POST requests to paths likely containing 'login' or 'password'.", "severity": "High", "conditions": lambda pkt_layers: "http" in pkt_layers and pkt_layers["http"].get("http.request.method") == "POST" and any(keyword in pkt_layers["http"].get("http.request.uri", "").lower() for keyword in ["login", "password", "auth", "signin"])},
    {"name": "SMBv1 Traffic Detected", "description": "Detects Server Message Block version 1 traffic, which is known to have vulnerabilities.", "severity": "High", "conditions": lambda pkt_layers: "smb" in pkt_layers and pkt_layers["smb"].get("smb.protocol_version") == "0x00000001"},
    {"name": "Cleartext Credentials (Basic Auth)", "description": "Detects HTTP Basic Authentication, which sends credentials in cleartext.", "severity": "High", "conditions": lambda pkt_layers: "http.authorization" in pkt_layers and "Basic" in pkt_layers["http"].get("http.authorization", "")},
    {"name": "Self-Signed Certificate (TLS)", "description": "Indicates a self-signed TLS certificate which can be a sign of MITM or internal testing.", "severity": "Medium", "conditions": lambda pkt_layers: "x509ce.self_signed" in pkt_layers and pkt_layers["x509ce"].get("x509ce.self_signed") == "1"},
    {"name": "Old TLS Version Used", "description": "Detects use of TLSv1.0 or TLSv1.1, which are considered insecure.", "severity": "Medium", "conditions": lambda pkt_layers: "tls" in pkt_layers and (pkt_layers["tls"].get("tls.handshake.version") == "0x0301" or pkt_layers["tls"].get("tls.handshake.version") == "0x0302")},
    {"name": "DNS Zone Transfer Attempt", "description": "Detects DNS AXFR queries, which could indicate reconnaissance.", "severity": "Medium", "conditions": lambda pkt_layers: "dns" in pkt_layers and pkt_layers["dns"].get("dns.qry.type") == "252"},
    {"name": "ICMP Large Packet (Potential Flood)", "description": "Detects unusually large ICMP packets, potentially indicative of a flood attack.", "severity": "Low", "conditions": lambda pkt_layers: "icmp" in pkt_layers and int(pkt_layers["ip"].get("ip.len", 0)) > 1500 if "ip" in pkt_layers else False},
    {"name": "ARP Spoofing Detected", "description": "Detects duplicate IP address usage, which can be a sign of ARP spoofing.", "severity": "High", "conditions": lambda pkt_layers: "arp" in pkt_layers and pkt_layers["arp"].get("arp.duplicate_address_detected") == "1"}
]

def check_predefined_rules(raw_packet_data_list):
    triggered_alerts = []
    for packet_data in raw_packet_data_list:
        details = packet_data.get("details", {})
        layers = details.get("layers", {})
        packet_number = details.get("frame", {}).get("frame.number", "N/A")

        for rule in PREDEFINED_RULES:
            try:
                if rule["conditions"](layers):
                    alert_message = f"{rule['description']} (Packet: {packet_number})"
                    triggered_alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "Predefined Rule",
                        "message": alert_message,
                        "severity": rule["severity"]
                    })
            except Exception as e:
                # Catch errors in rule conditions to prevent crashing
                st.exception(f"Error evaluating rule '{rule['name']}' for packet {packet_number}: {e}")
                log_action("RULE_EVAL_ERROR", {"rule": rule["name"], "packet_num": packet_number, "error": str(e)})
    return triggered_alerts

# --- Helper function to parse tshark -T ek JSON output ---
def _extract_packet_details_from_ek(packet_json_str):
    try:
        packet_data = json.loads(packet_json_str)
        # Tshark -T ek output has a "layers" key containing all protocol layers
        layers = packet_data.get("layers", {})

        # Attempt to get source and destination IPs for a quick summary
        src_ip, dst_ip = "N/A", "N/A"
        if "ip" in layers:
            src_ip = layers["ip"].get("ip.src")
            dst_ip = layers["ip"].get("ip.dst")
        elif "ipv6" in layers:
            src_ip = layers["ipv6"].get("ipv6.src")
            dst_ip = layers["ipv6"].get("ipv6.dst")

        # Get highest protocol layer for summary
        protocols = layers.get('frame', {}).get('frame.protocols', 'N/A')
        highest_protocol = protocols.split(':')[-1] if protocols != 'N/A' else 'N/A'

        # Get timestamp
        timestamp = packet_data.get("timestamp")

        summary = f"T:{timestamp} Src:{src_ip} Dst:{dst_ip} Proto:{highest_protocol}"
        return {"summary": summary, "details": packet_data}
    except json.JSONDecodeError:
        st.error("Failed to decode Tshark JSON output.")
        return None
    except Exception as e:
        st.error(f"Error parsing packet details: {e}")
        return None

# --- Wireshark/tshark Interaction Functions ---
def _process_pcap_file_with_tshark(pcap_file_path, bpf_filter=None):
    if not os.path.exists(pcap_file_path):
        st.error(f"PCAP file not found: {pcap_file_path}")
        return []

    tshark_command = [TSHARK_CMD, '-r', pcap_file_path, '-T', 'ek', '-P']
    if bpf_filter:
        tshark_command.extend(['-Y', bpf_filter])

    log_action("TSHARK_PROCESS_PCAP_START", {"pcap_path": pcap_file_path, "filter": bpf_filter})

    raw_packet_data = []
    try:
        # Using subprocess.Popen for streaming output to handle large files
        process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
        
        packet_buffer = []
        brace_count = 0
        
        # Read stdout line by line to parse JSON objects incrementally
        for line in iter(process.stdout.readline, ''):
            if '{' in line:
                brace_count += line.count('{')
                packet_buffer.append(line)
            else:
                packet_buffer.append(line)
            
            if '}' in line:
                brace_count -= line.count('}')
                if brace_count == 0 and packet_buffer:
                    full_json_str = "".join(packet_buffer)
                    parsed_packet = _extract_packet_details_from_ek(full_json_str)
                    if parsed_packet:
                        raw_packet_data.append(parsed_packet)
                    packet_buffer = []

        # Ensure process finishes and check for errors
        process.stdout.close()
        stderr_output = process.stderr.read()
        process.wait()

        if process.returncode != 0 and stderr_output:
            if "No such device" in stderr_output or "You don't have permission to capture" in stderr_output:
                st.error(f"Tshark permissions or interface error: {stderr_output}. Try running with sufficient privileges (e.g., sudo) or check interface name.")
                log_action("TSHARK_PERM_ERROR", {"error": stderr_output})
            elif "tshark: The capture session could not be initiated" in stderr_output:
                st.error(f"Tshark capture initiation failed: {stderr_output}. Ensure the interface is correct and not in use.")
                log_action("TSHARK_CAPTURE_INIT_ERROR", {"error": stderr_output})
            else:
                st.error(f"Tshark exited with error: {stderr_output}")
                log_action("TSHARK_PROCESS_PCAP_ERROR", {"error": stderr_output})
            return []

        log_action("TSHARK_PROCESS_PCAP_SUCCESS", {"pcap_path": pcap_file_path, "filter": bpf_filter, "num_packets": len(raw_packet_data)})
        return raw_packet_data

    except FileNotFoundError:
        st.error(f"{TSHARK_CMD} command not found. Please ensure Wireshark/tshark is installed and in your PATH.")
        log_action("TSHARK_NOT_FOUND")
        return []
    except Exception as e:
        st.error(f"An unexpected error occurred during tshark processing: {e}")
        log_action("TSHARK_PROCESS_PCAP_ERROR", {"error": str(e)})
        return []

def _convert_pyshark_packet_to_ek_format(pyshark_pkt, packet_num=None):
    """
    Converts a pyshark packet object into a dictionary structure
    similar to tshark -T ek -P JSON output.
    This is a simplification and may not be 100% identical.
    """
    if not pyshark_pkt:
        return None

    ek_format = {
        "timestamp": pyshark_pkt.sniff_time.isoformat(),
        "layers": {}
    }

    # Add frame layer details
    ek_format["layers"]["frame"] = {
        "frame.number": str(packet_num) if packet_num is not None else str(pyshark_pkt.number),
        "frame.time": pyshark_pkt.sniff_time.isoformat(),
        "frame.len": str(pyshark_pkt.length),
        "frame.cap_len": str(pyshark_pkt.captured_length),
        "frame.protocols": ":".join(pyshark_pkt.layers),
    }

    # Add other layers. pyshark exposes layers directly as attributes
    # We iterate through 'real' layers and convert their fields
    for layer_name in pyshark_pkt.layers:
        try:
            layer = pyshark_pkt.get_layer_by_name(layer_name)
            layer_dict = {}
            for field_name in layer.field_names:
                # pyshark uses '.' for subfields, tshark -T ek uses '_' for some, but typically keeps '.'
                # We'll use the pyshark field name directly.
                key = f"{layer_name}.{field_name}"
                value = str(layer.get_field(field_name).show) # .show gets the string representation

                # Special handling for certain fields that might be lists or require specific formatting
                if hasattr(layer.get_field(field_name), 'all_fields'):
                    # If it's a field with multiple instances (e.g., multiple DNS answers),
                    # pyshark might return a list of values.
                    all_values = [str(f.show) for f in layer.get_field(field_name).all_fields]
                    if len(all_values) > 1:
                        layer_dict[key] = all_values
                    else:
                        layer_dict[key] = value
                else:
                    layer_dict[key] = value

            ek_format["layers"][layer_name] = layer_dict
        except Exception as e:
            # st.warning(f"Could not convert layer {layer_name} from pyshark packet: {e}")
            pass # Skip problematic layers for now

    # Also try to extract ip.src and ip.dst explicitly for the summary display
    src_ip, dst_ip = "N/A", "N/A"
    if 'ip' in ek_format["layers"]:
        src_ip = ek_format["layers"]['ip'].get('ip.src', "N/A")
        dst_ip = ek_format["layers"]['ip'].get('ip.dst', "N/A")
    elif 'ipv6' in ek_format["layers"]:
        src_ip = ek_format["layers"]['ipv6'].get('ipv6.src', "N/A")
        dst_ip = ek_format["layers"]['ipv6'].get('ipv6.dst', "N/A")

    highest_protocol = pyshark_pkt.highest_layer if pyshark_pkt.highest_layer else 'N/A'
    summary = f"T:{pyshark_pkt.sniff_time.isoformat()} Src:{src_ip} Dst:{dst_ip} Proto:{highest_protocol}"

    return {"summary": summary, "details": ek_format}


def _process_live_packet_stream():
    """
    Function to be run in a separate thread to process live packets.
    """
    interface = st.session_state.live_capture_interface
    bpf_filter = st.session_state.active_capture_filter

    packet_counter = 0
    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter, use_json=True, include_raw=True)
        st.session_state.tshark_process = capture # Store the pyshark LiveCapture object
        st.session_state.is_capturing = True
        log_action("PYSHARK_LIVE_CAPTURE_STARTED", {"interface": interface, "filter": bpf_filter})
        
        for pkt in capture.sniff_continuously():
            if not st.session_state.is_capturing: # Check if stop has been requested
                break
            
            packet_counter += 1
            processed_pkt = _convert_pyshark_packet_to_ek_format(pkt, packet_num=packet_counter)
            if processed_pkt:
                # Append to raw_packet_data for later full processing/display
                st.session_state.raw_packet_data.append(processed_pkt)
                
                # Check against predefined rules in real-time
                realtime_alerts = check_predefined_rules([processed_pkt])
                if realtime_alerts:
                    st.session_state.alerts.extend(realtime_alerts)
                
                st.session_state.packets_in_live_capture = packet_counter
                # This reruns the UI sparingly to avoid excessive reruns
                if packet_counter % 5 == 0: # Rerun UI every 5 packets
                    st.rerun()

    except FileNotFoundError:
        st.error(f"Pyshark or Tshark not found. Ensure Wireshark/tshark is installed and in PATH.")
        log_action("PYSHARK_NOT_FOUND_ERROR")
    except Exception as e:
        st.error(f"Error during live capture processing: {e}")
        log_action("PYSHARK_LIVE_CAPTURE_ERROR", {"error": str(e)})
    finally:
        if st.session_state.tshark_process:
            st.session_state.tshark_process.close()
        st.session_state.is_capturing = False
        log_action("PYSHARK_LIVE_CAPTURE_STOPPED")
        # Ensure UI updates one last time after capture stops
        st.rerun()


def start_live_capture(interface, capture_filter):
    if st.session_state.is_capturing:
        st.warning("Live capture is already running.")
        return

    st.session_state.is_capturing = True
    st.session_state.active_capture_filter = capture_filter
    st.session_state.live_capture_interface = interface # Store interface for the thread
    st.session_state.packets_in_live_capture = 0
    st.session_state.raw_packet_data = [] # Clear previous data
    
    # Start the processing in a new thread
    st.session_state.live_capture_thread = threading.Thread(target=_process_live_packet_stream, daemon=True)
    st.session_state.live_capture_thread.start()
    
    log_action("LIVE_CAPTURE_START", {"interface": interface, "filter": capture_filter})
    st.success(f"Live capture started on {interface} with filter: '{capture_filter}'")


def stop_live_capture(bpf_filter_for_processing=None):
    if not st.session_state.is_capturing:
        st.warning("No live capture is currently running.")
        return
    
    st.session_state.is_capturing = False # Signal the thread to stop
    
    if st.session_state.tshark_process:
        # pyshark's LiveCapture doesn't have a direct 'stop' method that immediately exits
        # The loop in _process_live_packet_stream checks is_capturing flag
        # We might need a small delay or a more robust signal if the loop is stuck on sniffing
        pass # The loop will exit when is_capturing becomes False
    
    if st.session_state.live_capture_thread and st.session_state.live_capture_thread.is_alive():
        st.session_state.live_capture_thread.join(timeout=5) # Wait for the thread to finish
        if st.session_state.live_capture_thread.is_alive():
            st.error("Live capture thread did not terminate gracefully.")
            log_action("LIVE_CAPTURE_THREAD_TIMEOUT")
    
    log_action("LIVE_CAPTURE_STOP_INITIATED")
    st.success("Live capture stopped.")
    
    # After stopping, raw_packet_data contains all captured packets as processed_ek_format dicts
    # If full post-processing (e.g., saving to file and then processing with original _process_pcap_file_with_tshark)
    # is desired, it would need to reconstruct a pcap or directly use raw_packet_data for further analysis.
    
    st.session_state.packet_source_info = f"Live Capture ({st.session_state.live_capture_interface}, Filter: '{st.session_state.active_capture_filter}')"
    # Existing full processing call might be for tshark CLI, which expects a file.
    # For now, we rely on the pyshark processing to fill raw_packet_data.
    
    return f"Capture stopped. {st.session_state.packets_in_live_capture} packets processed."


def process_pcap_file(uploaded_file, bpf_filter=None):
    if uploaded_file is None:
        st.error("Please upload a PCAP file.")
        return "No file uploaded."

    # Create a temporary file to save the uploaded content
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        temp_pcap_path = tmp_file.name
    
    st.session_state.temp_capture_file_for_processing = temp_pcap_path # Store for later use
    st.session_state.last_processed_pcap_path = temp_pcap_path # Update the last processed path

    # Process the temporary file using tshark
    st.session_state.raw_packet_data = _process_pcap_file_with_tshark(temp_pcap_path, bpf_filter)
    
    # After processing, delete the temporary file if not needed
    # os.remove(temp_pcap_path) # Commented out if you want to keep it for later operations

    if st.session_state.raw_packet_data:
        st.session_state.current_pcap_session_id = log_pcap_session(uploaded_file.name, temp_pcap_path, bpf_filter, "Uploaded PCAP file")
        # Run predefined rules on the processed data
        st.session_state.alerts.extend(check_predefined_rules(st.session_state.raw_packet_data))
        return f"Processed {len(st.session_state.raw_packet_data)} packets from {uploaded_file.name} (Filter: {bpf_filter or 'None'})."
    else:
        st.session_state.current_pcap_session_id = None
        return f"No packets processed from {uploaded_file.name} (Filter: {bpf_filter or 'None'})."


def get_tshark_summary_stats(pcap_file_path, bpf_filter=None):
    if not pcap_file_path or not os.path.exists(pcap_file_path):
        return {"protocol_hierarchy": "N/A", "ip_conversations": "N/A"}

    stats = {}
    log_action("TSHARK_QUICK_STATS_RUN", {"pcap_path": pcap_file_path, "filter": bpf_filter})

    # Protocol Hierarchy Statistics
    try:
        proto_hierarchy_cmd = [TSHARK_CMD, '-r', pcap_file_path, '-q', '-z', 'io,phs']
        if bpf_filter:
            proto_hierarchy_cmd.extend(['-Y', bpf_filter])
        
        ph_process = subprocess.run(proto_hierarchy_cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace', timeout=30)
        # Extract the relevant part of the output
        phs_output = ph_process.stdout
        # Basic parsing: look for lines starting with '|' after a certain header
        phs_lines = []
        in_phs_section = False
        for line in phs_output.splitlines():
            if "Protocol Hierarchy Statistics" in line:
                in_phs_section = True
                continue
            if in_phs_section and line.startswith("|"):
                phs_lines.append(line)
            elif in_phs_section and not line.strip(): # End of section
                break
        
        stats["protocol_hierarchy"] = "\n".join(phs_lines) if phs_lines else "No protocol hierarchy statistics found."
    except subprocess.CalledProcessError as e:
        stats["protocol_hierarchy"] = f"Error getting protocol hierarchy: {e.stderr}"
    except subprocess.TimeoutExpired:
        stats["protocol_hierarchy"] = "Protocol hierarchy command timed out."
    except FileNotFoundError:
        st.error(f"{TSHARK_CMD} command not found.")
    except Exception as e:
        stats["protocol_hierarchy"] = f"An unexpected error occurred: {e}"

    # IP Conversation Statistics (basic)
    try:
        ip_conv_cmd = [TSHARK_CMD, '-r', pcap_file_path, '-q', '-z', 'conv,ip']
        if bpf_filter:
            ip_conv_cmd.extend(['-Y', bpf_filter])
        
        ip_process = subprocess.run(ip_conv_cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace', timeout=30)
        # Extract the relevant part of the output
        ip_conv_output = ip_process.stdout
        ip_conv_lines = []
        in_ip_conv_section = False
        for line in ip_conv_output.splitlines():
            if "IPv4 Conversations" in line or "IPv6 Conversations" in line:
                in_ip_conv_section = True
                ip_conv_lines.append(line) # Include the header
                continue
            if in_ip_conv_section and (line.startswith(" ") or line.startswith("<->")): # Lines for conversations
                ip_conv_lines.append(line)
            elif in_ip_conv_section and not line.strip(): # End of section
                break

        stats["ip_conversations"] = "\n".join(ip_conv_lines) if ip_conv_lines else "No IP conversation statistics found."

    except subprocess.CalledProcessError as e:
        stats["ip_conversations"] = f"Error getting IP conversations: {e.stderr}"
    except subprocess.TimeoutExpired:
        stats["ip_conversations"] = "IP conversations command timed out."
    except FileNotFoundError:
        st.error(f"{TSHARK_CMD} command not found.")
    except Exception as e:
        stats["ip_conversations"] = f"An unexpected error occurred: {e}"

    return stats


# --- Reporting Engine ---
def generate_html_report(analysis_results, user_query, packet_source, alerts_list, packet_summaries):
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Circuit Shark Analysis Report</title>
        <style>
            body {{ font-family: sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #333; }}
            .section {{ margin-bottom: 20px; padding: 15px; border: 1px solid #eee; border-radius: 5px; }}
            .alert {{ background-color: #ffe0e0; border-left: 5px solid red; padding: 10px; margin-bottom: 10px; }}
            .alert-medium {{ background-color: #fff8e0; border-left: 5px solid orange; }}
            .alert-low {{ background-color: #e0f2f7; border-left: 5px solid #00bcd4; }}
            pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }}
            .packet-summary {{ font-family: monospace; font-size: 0.9em; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>Circuit Shark Analysis Report</h1>
        <p><strong>Generated On:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <div class="section">
            <h2>Analysis Context</h2>
            <p><strong>Packet Source:</strong> {html.escape(packet_source)}</p>
            <p><strong>User Query/Focus:</strong> {html.escape(user_query)}</p>
        </div>
    """

    if alerts_list:
        html_content += """
        <div class="section">
            <h2>🚨 Alerts Found</h2>
        """
        for alert in alerts_list:
            severity_class = ""
            if alert['severity'].lower() == 'medium':
                severity_class = "alert-medium"
            elif alert['severity'].lower() == 'low':
                severity_class = "alert-low"
            
            html_content += f"""
            <div class="alert {severity_class}">
                <strong>Severity:</strong> {html.escape(alert['severity'])}<br>
                <strong>Source:</strong> {html.escape(alert['source'])}<br>
                <strong>Timestamp:</strong> {html.escape(alert['timestamp'])}<br>
                <strong>Message:</strong> {html.escape(alert['message'])}
            </div>
            """
        html_content += "</div>"

    if analysis_results:
        html_content += f"""
        <div class="section">
            <h2>🧠 LLM Analysis Results</h2>
            <pre>{html.escape(analysis_results)}</pre>
        </div>
        """
    
    if packet_summaries:
        html_content += """
        <div class="section">
            <h2>📦 Packet Summaries (Sample)</h2>
            <div class="packet-summary">
        """
        html_content += "\n".join([html.escape(s) for s in packet_summaries])
        html_content += """
            </div>
        </div>
        """

    html_content += """
    </body>
    </html>
    """
    return html_content

def format_markdown_report(analysis_results, user_query, packet_source, alerts_list, packet_summaries):
    markdown_content = f"""
# Circuit Shark Analysis Report

**Generated On:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Analysis Context
- **Packet Source:** {packet_source}
- **User Query/Focus:** {user_query}

"""

    if alerts_list:
        markdown_content += """
## 🚨 Alerts Found

"""
        for alert in alerts_list:
            markdown_content += f"""
- **Severity:** {alert['severity']}
  - **Source:** {alert['source']}
  - **Timestamp:** {alert['timestamp']}
  - **Message:** {alert['message']}
"""
        markdown_content += "\n"

    if analysis_results:
        markdown_content += f"""
## 🧠 LLM Analysis Results

```
{analysis_results}
```
"""
    if packet_summaries:
        markdown_content += """
## 📦 Packet Summaries (Sample)
```
"""
        markdown_content += "\n".join(packet_summaries)
        markdown_content += """
```
"""
    return markdown_content

def generate_pdf_from_html(html_string):
    if not WEASYPRINT_AVAILABLE:
        st.error("WeasyPrint is not installed. PDF generation is not available.")
        return None
    try:
        # WeasyPrint requires bytes-like object for HTML.write_pdf
        pdf_bytes = WeasyHTML(string=html_string).write_pdf()
        return pdf_bytes
    except Exception as e:
        st.error(f"Error generating PDF: {e}")
        return None

# --- Traffic Statistics Functions ---
def get_protocol_distribution(raw_packet_data):
    protocol_counts = Counter()
    for packet in raw_packet_data:
        layers = packet.get("details", {}).get("layers", {})
        if "frame" in layers:
            protocols_str = layers["frame"].get("frame.protocols", "")
            # protocols_str is like "eth:ip:tcp:http"
            parts = protocols_str.split(':')
            for proto in parts:
                if proto: # Ensure it's not empty string
                    protocol_counts[proto] += 1
    return protocol_counts

def get_top_ips(raw_packet_data, ip_type="src", top_n=TOP_N_STATS):
    ip_counts = Counter()
    for packet in raw_packet_data:
        layers = packet.get("details", {}).get("layers", {})
        ip_layer_name = None
        if "ip" in layers:
            ip_layer_name = "ip"
        elif "ipv6" in layers:
            ip_layer_name = "ipv6"
        
        if ip_layer_name:
            ip_address = layers[ip_layer_name].get(f"{ip_layer_name}.{ip_type}")
            if ip_address:
                ip_counts[ip_address] += 1
    return ip_counts.most_common(top_n)


# --- Threat Intelligence Functions ---
def is_public_ip(ip_address_str):
    """Checks if an IP address is public."""
    try:
        ip = ipaddress.ip_address(ip_address_str)
        # Check if it's not a private, loopback, link-local, multicast, reserved, or unspecified IP
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False # Not a valid IP address

async def check_ip_abuseipdb(ip_address):
    """Checks a public IP address against AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return None
    if not is_public_ip(ip_address):
        return None

    # Check cache
    cached_data = st.session_state.abuseipdb_cache.get(ip_address)
    if cached_data and (datetime.now() - cached_data["timestamp"] < timedelta(minutes=ABUSEIPDB_CACHE_EXPIRY_MINUTES)):
        return cached_data["data"]

    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': ''}
    
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
                intel_summary = {"ipAddress": ip_address, "abuseConfidenceScore": 0, "totalReports": 0, "notes": "Not found in AbuseIPDB or no abuse reported."}
                st.session_state.abuseipdb_cache[ip_address] = {"timestamp": datetime.now(), "data": intel_summary}
                return intel_summary

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429: # Rate limit
            st.warning(f"AbuseIPDB rate limit hit. Skipping further checks for a while. IP: {ip_address}")
            st.session_state.abuseipdb_rate_limited_until = datetime.now() + timedelta(minutes=15)
            log_action("THREAT_INTEL_RATE_LIMIT_HIT", {"service": "AbuseIPDB", "ip": ip_address, "status_code": 429})
        elif e.response.status_code == 402: # Payment required (e.g. if using a paid feature on free key)
             st.warning(f"AbuseIPDB: Payment required or feature not available on current plan for IP: {ip_address}")
             log_action("THREAT_INTEL_ERROR", {"service": "AbuseIPDB", "ip": ip_address, "error": f"HTTP {e.response.status_code} - {e.response.text[:50]}"})
        else:
            st.caption(f"AbuseIPDB HTTP Error for {ip_address}: {e.response.status_code} - {e.response.text[:100]}")
            log_action("THREAT_INTEL_ERROR", {"service": "AbuseIPDB", "ip": ip_address, "error": f"HTTP {e.response.status_code} - {e.response.text[:50]}"})
    except httpx.RequestError as e:
        st.caption(f"AbuseIPDB Request Error for {ip_address}: {e}")
        log_action("THREAT_INTEL_ERROR", {"service": "AbuseIPDB", "ip": ip_address, "error": f"Request Error: {e}"})
    except Exception as e:
        st.caption(f"Unexpected error checking AbuseIPDB for {ip_address}: {e}")
        log_action("THREAT_INTEL_ERROR", {"service": "AbuseIPDB", "ip": ip_address, "error": str(e)})
    return None

async def check_ip_geolocationio(ip_address):
    """Checks a public IP address against ipgeolocation.io."""
    if not IPGEOLOCATION_API_KEY:
        return None
    if not is_public_ip(ip_address):
        return None

    # Check cache
    cached_data = st.session_state.ipgeolocation_cache.get(ip_address)
    if cached_data and (datetime.now() - cached_data["timestamp"] < timedelta(minutes=IPGEOLOCATION_CACHE_EXPIRY_MINUTES)):
        return cached_data["data"]

    params = {'apiKey': IPGEOLOCATION_API_KEY, 'ip': ip_address}
    
    log_action("THREAT_INTEL_IPGEOLOCATION_LOOKUP", {"ip": ip_address})
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(IPGEOLOCATION_API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Store relevant fields
            intel_summary = {
                "ip": data.get("ip"),
                "country_name": data.get("country_name"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "organization": data.get("organization"),
                "is_tor": data.get("is_tor", False)
            }
            st.session_state.ipgeolocation_cache[ip_address] = {"timestamp": datetime.now(), "data": intel_summary}
            return intel_summary

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429: # Rate limit
            st.warning(f"ipgeolocation.io rate limit hit. Skipping further checks for a while. IP: {ip_address}")
            st.session_state.ipgeolocation_rate_limited_until = datetime.now() + timedelta(minutes=15)
            log_action("THREAT_INTEL_RATE_LIMIT_HIT", {"service": "IPGeolocation", "ip": ip_address, "status_code": 429})
        elif e.response.status_code in [401, 403]: # Auth error
             st.error(f"ipgeolocation.io: Invalid API Key or permission error for IP: {ip_address}")
             log_action("THREAT_INTEL_ERROR", {"service": "IPGeolocation", "ip": ip_address, "error": f"HTTP {e.response.status_code} - {e.response.text[:50]}"})
        else:
            st.caption(f"ipgeolocation.io HTTP Error for {ip_address}: {e.response.status_code} - {e.response.text[:100]}")
            log_action("THREAT_INTEL_ERROR", {"service": "IPGeolocation", "ip": ip_address, "error": f"HTTP {e.response.status_code} - {e.response.text[:50]}"})
    except httpx.RequestError as e:
        st.caption(f"ipgeolocation.io Request Error for {ip_address}: {e}")
        log_action("THREAT_INTEL_ERROR", {"service": "IPGeolocation", "ip": ip_address, "error": f"Request Error: {e}"})
    except Exception as e:
        st.caption(f"Unexpected error checking ipgeolocation.io for {ip_address}: {e}")
        log_action("THREAT_INTEL_ERROR", {"service": "IPGeolocation", "ip": ip_address, "error": str(e)})
    return None

async def run_threat_intelligence_checks():
    """Extracts unique public IPs and checks them against AbuseIPDB and ipgeolocation.io."""
    if not st.session_state.raw_packet_data:
        return

    abuseipdb_paused = st.session_state.get("abuseipdb_rate_limited_until") and datetime.now() < st.session_state.abuseipdb_rate_limited_until
    geolocation_paused = st.session_state.get("ipgeolocation_rate_limited_until") and datetime.now() < st.session_state.ipgeolocation_rate_limited_until

    if abuseipdb_paused:
        st.caption(f"AbuseIPDB checks paused due to rate limiting until {st.session_state.abuseipdb_rate_limited_until.strftime('%H:%M:%S')}.")
    if geolocation_paused:
        st.caption(f"ipgeolocation.io checks paused due to rate limiting until {st.session_state.ipgeolocation_rate_limited_until.strftime('%H:%M:%S')}.")

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

    # Ensure results dicts exist
    st.session_state.ip_threat_intel_results = st.session_state.get("ip_threat_intel_results", {})
    st.session_state.ip_geolocation_results = st.session_state.get("ip_geolocation_results", {})
    
    tasks = []
    
    ips_to_check_abuseipdb = []
    if not abuseipdb_paused:
        ips_to_check_abuseipdb = [ip for ip in unique_public_ips if ip not in st.session_state.abuseipdb_cache or \
                                     (datetime.now() - st.session_state.abuseipdb_cache[ip]["timestamp"] > timedelta(minutes=ABUSEIPDB_CACHE_EXPIRY_MINUTES))]
        tasks.extend([check_ip_abuseipdb(ip) for ip in ips_to_check_abuseipdb])

    ips_to_check_geolocation = []
    if not geolocation_paused:
        ips_to_check_geolocation = [ip for ip in unique_public_ips if ip not in st.session_state.ipgeolocation_cache or \
                                       (datetime.now() - st.session_state.ipgeolocation_cache[ip]["timestamp"] > timedelta(minutes=IPGEOLOCATION_CACHE_EXPIRY_MINUTES))]
        tasks.extend([check_ip_geolocationio(ip) for ip in ips_to_check_geolocation])

    # Load cached data for IPs we *aren't* checking to ensure all unique IPs appear in the summary
    for ip in unique_public_ips:
        if ip not in ips_to_check_abuseipdb and ip in st.session_state.abuseipdb_cache:
            st.session_state.ip_threat_intel_results[ip] = st.session_state.abuseipdb_cache[ip]["data"]
        if ip not in ips_to_check_geolocation and ip in st.session_state.ipgeolocation_cache:
            st.session_state.ip_geolocation_results[ip] = st.session_state.ipgeolocation_cache[ip]["data"]
            
    if not tasks:
        st.session_state.ip_threat_intel_summary_message = f"All {len(unique_public_ips)} unique public IPs already have recent intel (cached)."
        return

    st.session_state.ip_threat_intel_summary_message = f"Checking {len(ips_to_check_abuseipdb)} IPs (AbuseIPDB) and {len(ips_to_check_geolocation)} IPs (Geolocation)..."
    
    results = await asyncio.gather(*tasks)
    
    flagged_abuse_count = 0
    flagged_tor_count = 0
    
    for ip_intel in results:
        if ip_intel:
            # Check if it's an AbuseIPDB result
            if "abuseConfidenceScore" in ip_intel:
                ip_addr = ip_intel["ipAddress"]
                st.session_state.ip_threat_intel_results[ip_addr] = ip_intel
                score = ip_intel.get("abuseConfidenceScore", 0)
                if score >= 75:
                    flagged_abuse_count += 1
                    st.session_state.alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "Threat Intel (AbuseIPDB)",
                        "message": f"High abuse score ({score}%) for IP: {ip_addr}. Country: {ip_intel.get('countryCode','N/A')}, Usage: {ip_intel.get('usageType','N/A')}, ISP: {ip_intel.get('isp','N/A')}, Reports: {ip_intel.get('totalReports',0)}",
                        "severity": "High"
                    })
                elif score >= 50:
                     st.session_state.alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "Threat Intel (AbuseIPDB)",
                        "message": f"Moderate abuse score ({score}%) for IP: {ip_addr}. Check details.",
                        "severity": "Medium"
                    })
            
            # Check if it's an ipgeolocation.io result
            elif "country_name" in ip_intel:
                ip_addr = ip_intel["ip"]
                st.session_state.ip_geolocation_results[ip_addr] = ip_intel
                if ip_intel.get("is_tor"):
                    flagged_tor_count += 1
                    st.session_state.alerts.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "Threat Intel (ipgeolocation.io)",
                        "message": f"TOR Node Detected for IP: {ip_addr}. Country: {ip_intel.get('country_name','N/A')}, ISP: {ip_intel.get('isp','N/A')}",
                        "severity": "High"
                    })

    total_abuse_intel = len(st.session_state.ip_threat_intel_results)
    total_geo_intel = len(st.session_state.ip_geolocation_results)
    st.session_state.ip_threat_intel_summary_message = (
        f"Intel Check: {total_abuse_intel} IPs have AbuseIPDB data (flagged {flagged_abuse_count} new). "
        f"{total_geo_intel} IPs have Geolocation data (flagged {flagged_tor_count} new TOR)."
    )
    log_action("THREAT_INTEL_RUN_COMPLETED", {
        "unique_ips_total": len(unique_public_ips), 
        "ips_checked_abuseipdb": len(ips_to_check_abuseipdb), 
        "ips_checked_geolocation": len(ips_to_check_geolocation), 
        "flagged_abuse_new": flagged_abuse_count,
        "flagged_tor_new": flagged_tor_count
    })


# --- Packet Translation Function ---
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
        result = await call_gemini_api(constructed_prompt, packet_json_str, template_key, "translate this packet")
        
        st.session_state.packet_translation_output = result.get("text", "Translation failed.")
        log_action("PACKET_TRANSLATION_SUCCESS", {"packet_index": packet_index, "translation": result.get("text", "")})
    
    except Exception as e:
        st.session_state.packet_translation_output = f"Error during translation: {e}"
        log_action("PACKET_TRANSLATION_ERROR", {"packet_index": packet_index, "error": str(e)})


# --- Streamlit App UI ---
st.set_page_config(page_title=APP_TITLE, layout="wide")
if 'db_initialized' not in st.session_state:
    init_db()
    st.session_state.db_initialized = True
    log_action("APP_START")

st.title(f"{APP_TITLE} - Network Traffic Analysis with AI")

async def main_ui():
    with st.sidebar:
        st.header("⚙️ Controls & Configuration")
        
        st.subheader("🚨 Alert Overview")
        # Display current number of alerts
        num_alerts = len(st.session_state.alerts)
        if num_alerts > 0:
            st.warning(f"Total Alerts: {num_alerts}")
            high_alerts = sum(1 for a in st.session_state.alerts if a['severity'] == 'High')
            medium_alerts = sum(1 for a in st.session_state.alerts if a['severity'] == 'Medium')
            low_alerts = sum(1 for a in st.session_state.alerts if a['severity'] == 'Low')
            st.caption(f"High: {high_alerts}, Medium: {medium_alerts}, Low: {low_alerts}")
        else:
            st.info("No alerts yet.")

        st.markdown("---")
        # API Key Checks
        if not GEMINI_API_KEY: st.caption("⚠️ Gemini AI limited (API key N/A).")
        if not MISTRAL_API_KEY: st.caption("⚠️ Mistral AI limited (API key N/A).")
        if not GROQ_API_KEY: st.caption("⚠️ Groq AI limited (API key N/A).")
        if not ABUSEIPDB_API_KEY: st.caption("⚠️ AbuseIPDB Threat Intel limited (API key N/A).")
        if not IPGEOLOCATION_API_KEY: st.caption("⚠️ IP Geolocation limited (API key N/A).")

        # LLM Rate Limit Status
        if st.session_state.get("gemini_rate_limited_until") and datetime.now() < st.session_state.gemini_rate_limited_until:
            st.caption(f"⚠️ Gemini is rate-limited until {st.session_state.gemini_rate_limited_until.strftime('%H:%M:%S')}.")
        if st.session_state.get("mistral_rate_limited_until") and datetime.now() < st.session_state.mistral_rate_limited_until:
            st.caption(f"⚠️ Mistral is rate-limited until {st.session_state.mistral_rate_limited_until.strftime('%H:%M:%S')}.")
        if st.session_state.get("groq_rate_limited_until") and datetime.now() < st.session_state.groq_rate_limited_until:
            st.caption(f"⚠️ Groq is rate-limited until {st.session_state.groq_rate_limited_until.strftime('%H:%M:%S')}.")

        st.markdown("---")

        st.subheader("📦 Packet Source")
        source_option = st.radio("Packet Source:", ("Live Capture", "Upload PCAP"), key="src_opt_radio_ti")
        
        # Consistent BPF filter input for both capture types
        st.session_state.manual_capture_filter_value = st.text_input(
            "BPF Filter (e.g., 'port 80 or port 443'):",
            value=st.session_state.get("manual_capture_filter_value", ""),
            key="manual_capture_filter_input"
        )
        # NLP suggested filter overrides manual if present
        active_capture_filter_for_live = st.session_state.nlp_suggested_filter if st.session_state.nlp_suggested_filter else st.session_state.manual_capture_filter_value

        if source_option == "Live Capture":
            # List available interfaces for pyshark
            try:
                available_interfaces = pyshark.LiveCapture.interfaces()
                if not available_interfaces:
                    st.warning("No network interfaces found. Please ensure `tshark` is installed and properly configured.")
                    interface_selected = ""
                else:
                    interface_selected = st.selectbox("Select Network Interface:", available_interfaces, key="interface_select_ti")
            except Exception as e:
                st.error(f"Could not list interfaces. Ensure Tshark is installed and in PATH. Error: {e}")
                interface_selected = ""

            col_live_cap_start, col_live_cap_stop = st.columns(2)
            with col_live_cap_start:
                if st.button("🚀 Start Live Capture", key="start_cap_ti", disabled=st.session_state.is_capturing or not interface_selected):
                    # Clear old data before new capture
                    st.session_state.raw_packet_data = []
                    st.session_state.alerts = []
                    st.session_state.llm_analysis_results = []
                    st.session_state.ip_threat_intel_results = {}
                    st.session_state.ip_geolocation_results = {}
                    st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
                    st.session_state.packet_translation_output = "" # Clear translation
                    st.session_state.last_translated_packet_index = None

                    with st.spinner(f"Starting live capture on {interface_selected}..."):
                        start_live_capture(interface_selected, active_capture_filter_for_live)
                    st.rerun() # Rerun to update UI with capture status
            with col_live_cap_stop:
                if st.button("🛑 Stop Live Capture", key="stop_cap_ti", disabled=not st.session_state.is_capturing):
                    with st.spinner("Stopping capture and processing..."):
                        stop_live_capture(bpf_filter_for_processing=active_capture_filter_for_live)
                    # Automatically run threat intel checks after stopping live capture and processing
                    if st.session_state.raw_packet_data:
                        with st.spinner("Running threat intelligence checks..."):
                            await run_threat_intelligence_checks()
                        st.rerun() # To update the display with TI results/alerts
            
            if st.session_state.is_capturing:
                st.info(f"Capturing... Packets: {st.session_state.packets_in_live_capture}")
                # Provide a button to trigger manual UI refresh, as auto-rerun is limited
                if st.button("Refresh Live View", key="refresh_live_view"):
                    st.rerun()

        elif source_option == "Upload PCAP":
            uploaded_file = st.file_uploader("Upload PCAP/NG", type=["pcap","pcapng","cap"], key="pcap_up_ti")
            st.session_state.pcap_processing_filter = st.text_input("BPF Filter for this PCAP (optional, overrides global filter):", value=st.session_state.get("pcap_processing_filter",""), key="pcap_proc_filter_input_ti")
            if uploaded_file and st.button("📄 Process PCAP File", key="proc_pcap_ti"):
                # Clear previous state
                st.session_state.raw_packet_data = []
                st.session_state.alerts = []
                st.session_state.llm_analysis_results = []
                st.session_state.ip_threat_intel_results = {}
                st.session_state.ip_geolocation_results = {}
                st.session_state.ip_threat_intel_summary_message = "Threat intelligence checks not yet run for this data."
                st.session_state.packet_translation_output = "" # Clear translation
                st.session_state.last_translated_packet_index = None

                with st.spinner(f"Processing {uploaded_file.name}..."):
                    status = process_pcap_file(uploaded_file, bpf_filter=st.session_state.pcap_processing_filter)
                    st.success(status)
                # Automatically run threat intel checks after processing PCAP
                if st.session_state.raw_packet_data:
                    with st.spinner("Running threat intelligence checks..."):
                        await run_threat_intelligence_checks()
                    st.rerun()
        
        # Manual Threat Intel Check Button
        if st.session_state.raw_packet_data:
            st.markdown("---")
            st.subheader("🛡️ Threat Intelligence")
            if st.button("Run/Refresh IP Threat Intel Checks", key="manual_ti_check_btn"):
                with st.spinner("Running threat intelligence checks..."):
                    await run_threat_intelligence_checks()
                st.rerun()
        
        st.markdown("---")
        st.subheader("🧠 LLM Analysis")
        # Select which LLM to use
        selected_llm = st.selectbox("Select LLM:", LLM_OPTIONS, key="llm_select")
        
        # Select prompt template
        prompt_template_options = list(PROMPT_TEMPLATES.keys())
        st.session_state.current_prompt_template = st.selectbox(
            "Analysis Focus:",
            prompt_template_options,
            index=prompt_template_options.index(st.session_state.current_prompt_template),
            key="prompt_template_select"
        )
        
        st.session_state.usr_q_add_in = st.text_area("Additional Query Details (for LLM):", value=st.session_state.get("usr_q_add_in", ""), height=100)
        st.session_state.num_pkts_llm_in = st.number_input("Number of Packets to Analyze (max):", min_value=1, max_value=len(st.session_state.raw_packet_data) if st.session_state.raw_packet_data else 1, value=min(10, len(st.session_state.raw_packet_data)) if st.session_state.raw_packet_data else 1, key="num_pkts_llm_in_ti")

        if st.button("Start LLM Analysis", key="run_llm_analysis", disabled=not st.session_state.raw_packet_data):
            if not st.session_state.raw_packet_data:
                st.warning("Please capture or upload packet data first.")
            else:
                log_action("LLM_ANALYSIS_REQUEST", {"llm": selected_llm, "template": st.session_state.current_prompt_template, "query_addon": st.session_state.usr_q_add_in, "num_packets": st.session_state.num_pkts_llm_in})
                with st.spinner(f"Running {selected_llm} analysis..."):
                    selected_packets_for_llm = st.session_state.raw_packet_data[:st.session_state.num_pkts_llm_in]
                    packet_data_json_list_str = json.dumps([p["details"] for p in selected_packets_for_llm], indent=2)
                    
                    analysis_text = ""
                    new_alerts = []

                    prompt_base = PROMPT_TEMPLATES[st.session_state.current_prompt_template]
                    constructed_prompt = f"{prompt_base}\n{st.session_state.usr_q_add_in}"

                    if selected_llm == "Google Gemini":
                        result = await call_gemini_api(constructed_prompt, packet_data_json_list_str, st.session_state.current_prompt_template, st.session_state.usr_q_add_in)
                        analysis_text = result["text"]
                        new_alerts.extend(result["alerts"])
                    elif selected_llm == "Mistral AI":
                        result = await call_mistral_api(constructed_prompt, packet_data_json_list_str, st.session_state.current_prompt_template, st.session_state.usr_q_add_in)
                        analysis_text = result["text"]
                        new_alerts.extend(result["alerts"])
                    elif selected_llm == "Groq":
                        result = await call_groq_api(constructed_prompt, packet_data_json_list_str, st.session_state.current_prompt_template, st.session_state.usr_q_add_in)
                        analysis_text = result["text"]
                        new_alerts.extend(result["alerts"])
                    elif selected_llm == "All (Sequential)":
                        llm_results = {}
                        for llm in ["Google Gemini", "Mistral AI", "Groq"]:
                            st.info(f"Running {llm}...")
                            llm_call_func = globals()[f"call_{llm.lower().replace(' ', '_')}_api"] # Dynamic function call
                            result = await llm_call_func(constructed_prompt, packet_data_json_list_str, st.session_state.current_prompt_template, st.session_state.usr_q_add_in)
                            llm_results[llm] = result["text"]
                            new_alerts.extend(result["alerts"])
                            analysis_text += f"\n\n--- {llm} Analysis ---\n{result['text']}"
                        st.success("All LLMs finished analysis.")

                    st.session_state.llm_analysis_results = analysis_text
                    st.session_state.alerts.extend(new_alerts)
                    
                    # Log LLM analysis to DB
                    if st.session_state.current_pcap_session_id:
                        log_llm_analysis(st.session_state.current_pcap_session_id, selected_llm, st.session_state.current_prompt_template, st.session_state.usr_q_add_in, analysis_text, new_alerts)
                    
                    st.rerun() # Rerun to display results

        st.markdown("---")
        st.subheader("📄 Reporting")
        report_format = st.selectbox("Select Report Format:", REPORT_FORMATS, key="report_format_select")
        st.session_state.current_report_format = report_format

        if st.button("Generate Report", key="generate_report_btn", disabled=not st.session_state.raw_packet_data):
            with st.spinner("Generating report..."):
                report_llm_analysis = st.session_state.llm_analysis_results if st.session_state.llm_analysis_results else "No LLM analysis performed."
                report_packet_source = st.session_state.packet_source_info if st.session_state.packet_source_info else "N/A"
                report_user_query = f"Analysis Focus: {st.session_state.current_prompt_template}"
                if st.session_state.usr_q_add_in:
                    report_user_query += f"\nAdditional Details: {st.session_state.usr_q_add_in}"
                
                # Get a sample of packet summaries for the report
                sample_packet_summaries = [pkt["summary"] for pkt in st.session_state.raw_packet_data[:10]] # First 10 packets

                if report_format == "Markdown":
                    st.session_state.current_report_content = format_markdown_report(report_llm_analysis, report_user_query, report_packet_source, st.session_state.alerts, sample_packet_summaries)
                elif report_format == "HTML":
                    st.session_state.current_report_content = generate_html_report(report_llm_analysis, report_user_query, report_packet_source, st.session_state.alerts, sample_packet_summaries)
                elif report_format == "PDF":
                    html_report_content = generate_html_report(report_llm_analysis, report_user_query, report_packet_source, st.session_state.alerts, sample_packet_summaries)
                    pdf_bytes = generate_pdf_from_html(html_report_content)
                    if pdf_bytes:
                        # Encode PDF bytes to base64 for download link
                        b64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                        st.session_state.current_report_content = f'<a href="data:application/pdf;base64,{b64_pdf}" download="circuit_shark_report.pdf">Download PDF Report</a>'
                    else:
                        st.session_state.current_report_content = "PDF generation failed. See error messages above."
                st.success("Report Generated!")
                st.rerun()
        
        st.markdown("---")
        st.subheader("🤖 NLP Command Interface")
        user_nlp_command = st.text_input("Enter command (e.g., 'show HTTP traffic from 192.168.1.1', 'analyze DNS for suspicious domains'):", key="nlp_command_input")
        if st.button("Interpret Command", key="interpret_nlp_btn"):
            if user_nlp_command:
                # Add current command to history
                st.session_state.nlp_command_history.append(user_nlp_command)
                command_history_str = "\n".join(list(st.session_state.nlp_command_history))

                with st.spinner("Interpreting command with LLM..."):
                    interpretation = await interpret_command_with_llm(user_nlp_command, command_history_str)
                    st.session_state.nlp_interpretation_notes = interpretation.get("interpretation_notes", "No specific notes.")
                    
                    bpf_filter = interpretation.get("bpf_filter", "")
                    llm_analysis_focus = interpretation.get("llm_analysis_focus", "general_analysis")
                    llm_query_addon = interpretation.get("llm_query_addon", "")
                    tshark_fields_to_extract = [f.strip() for f in interpretation.get("tshark_fields_to_extract", "").split(',') if f.strip()]
                    command_type = interpretation.get("command_type", "analytical_query")

                    # Update relevant session state variables based on interpretation
                    if bpf_filter:
                        st.session_state.nlp_suggested_filter = bpf_filter
                        st.info(f"Suggested BPF Filter: `{bpf_filter}` (Applied to capture/processing)")
                    else:
                        st.session_state.nlp_suggested_filter = ""
                        st.info("No specific BPF filter suggested by LLM.")

                    st.session_state.current_prompt_template = llm_analysis_focus
                    st.session_state.usr_q_add_in = llm_query_addon
                    st.info(f"LLM Analysis Focus Set: `{llm_analysis_focus}`. Query Add-on: `{llm_query_addon}`")

                    if tshark_fields_to_extract:
                        st.info(f"Suggested fields for extraction: `{', '.join(tshark_fields_to_extract)}`")
                        # Automatically run field extraction if data is available
                        if st.session_state.raw_packet_data and st.session_state.last_processed_pcap_path:
                            with st.spinner("Running field extraction..."):
                                st.session_state.field_extraction_df = run_tshark_field_extraction(tshark_fields_to_extract, bpf_filter if bpf_filter else st.session_state.active_capture_filter, st.session_state.last_processed_pcap_path)
                                if not st.session_state.field_extraction_df.empty:
                                    st.success("Field extraction complete!")
                                else:
                                    st.warning("Field extraction yielded no results.")
                        else:
                            st.warning("No PCAP data loaded to perform field extraction.")
                    else:
                        st.session_state.field_extraction_df = pd.DataFrame() # Clear previous extraction results
                    
                    st.rerun() # Rerun to apply new settings and potentially display extraction results
            else:
                st.warning("Please enter a command for NLP interpretation.")
        
        if st.session_state.nlp_interpretation_notes:
            st.caption(f"NLP Notes: {st.session_state.nlp_interpretation_notes}")
        
        st.markdown("---"); st.caption(f"Circuit Shark v1.8 (Real-Time Alerts, LLM Rate Limiting)")


    # --- Main Area for Display ---
    # Display tshark -z Summary Stats (if generated)
    if st.session_state.get("tshark_summary_stats"):
        st.header("📈 tshark Summary Statistics")
        st.json(st.session_state.tshark_summary_stats, expanded=False)
        st.markdown("---")
    
    # Display Traffic Analysis Dashboard (if data exists)
    if st.session_state.get("raw_packet_data"):
        st.header("📊 Traffic Analysis Dashboard")
        
        col_dist, col_ips = st.columns(2)
        with col_dist:
            st.subheader("Protocol Distribution")
            proto_dist = get_protocol_distribution(st.session_state.raw_packet_data)
            if proto_dist:
                proto_df = pd.DataFrame(proto_dist.items(), columns=["Protocol", "Count"])
                fig = px.bar(proto_df, x="Protocol", y="Count", title="Protocol Distribution")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No protocol data available.")

        with col_ips:
            st.subheader("Top Source IPs")
            top_src_ips = get_top_ips(st.session_state.raw_packet_data, ip_type="src")
            if top_src_ips:
                src_ip_df = pd.DataFrame(top_src_ips, columns=["IP", "Count"])
                fig = px.bar(src_ip_df, x="IP", y="Count", title="Top Source IPs")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No source IP data available.")
            
            st.subheader("Top Destination IPs")
            top_dst_ips = get_top_ips(st.session_state.raw_packet_data, ip_type="dst")
            if top_dst_ips:
                dst_ip_df = pd.DataFrame(top_dst_ips, columns=["IP", "Count"])
                fig = px.bar(dst_ip_df, x="IP", y="Count", title="Top Destination IPs")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No destination IP data available.")

        st.markdown("---")

    # Display Quick Field Extraction Results (if generated)
    if st.session_state.field_extraction_df is not None and not st.session_state.field_extraction_df.empty:
        st.subheader("🔬 Quick Field Extraction Results")
        st.dataframe(st.session_state.field_extraction_df)
        st.markdown("---")

    # Main content columns for Packet Log, LLM Analysis & Alerts
    col1_main, col2_main = st.columns([2,3])
    with col1_main:
        st.header("📦 Packet Data Log")
        if st.session_state.raw_packet_data:
            packet_summaries = [p["summary"] for p in st.session_state.raw_packet_data]
            
            # Display packets with selection
            for i, summary in enumerate(packet_summaries):
                if st.button(summary, key=f"packet_summary_{i}"):
                    st.session_state.selected_packet_index = i
                    st.rerun() # Rerun to display details
            
            if st.session_state.selected_packet_index is not None:
                st.subheader(f"Pkt {st.session_state.selected_packet_index + 1} Details")
                try:
                    idx = st.session_state.selected_packet_index
                    selected_pkt_details = st.session_state.raw_packet_data[idx]["details"]
                    
                    st.json(selected_pkt_details, expanded=False)

                    # Display Threat Intel for IPs in this selected packet
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
                            
                            # Display AbuseIPDB Intel
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
                            
                            # Display Geolocation Intel
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

                    st.markdown("---") # Separator
                    if st.button("🧠 Translate this packet with AI", key=f"translate_btn_{idx}"):
                        with st.spinner(f"Translating Packet {idx + 1}..."):
                            packet_json_str = json.dumps(selected_pkt_details)
                            await translate_single_packet(packet_json_str, idx) 
                            st.rerun()

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
            else:
                st.info("Select a packet from the list above to view its full details and threat intelligence.")
        else:
            st.info("No packet data loaded. Please start a live capture or upload a PCAP file.")
            
    with col2_main:
        st.header("💡 LLM Analysis & Alerts")
        # Display Threat Intel Summary Message
        if st.session_state.get("ip_threat_intel_summary_message"):
            st.info(st.session_state.ip_threat_intel_summary_message)
            st.markdown("---")

        if st.session_state.alerts:
            st.subheader("🚨 Alerts!")
            sorted_alerts = sorted(st.session_state.alerts, key=lambda x: {"High":0, "Medium":1, "Low":2}.get(x['severity'], 3))
            for alert in sorted_alerts:
                color = "red" if alert['severity'] == "High" else "orange" if alert['severity'] == "Medium" else "blue"
                st.markdown(f"<p style='color:{color};'><b>[{alert['severity']}]</b> {alert['message']} <br> <i>({alert['source']} @ {alert['timestamp']})</i></p>", unsafe_allow_html=True)
            st.markdown("---")
        else:
            st.info("No alerts generated yet from LLM or predefined rules.")

        if st.session_state.llm_analysis_results:
            st.subheader("LLM Insights:")
            st.markdown(st.session_state.llm_analysis_results)
        else:
            st.info("No LLM analysis results yet. Run an analysis from the sidebar.")
    
    st.markdown("---")
    st.header("📋 Generated Report Preview")
    if st.session_state.current_report_content:
        if st.session_state.current_report_format == "HTML" or st.session_state.current_report_format == "PDF":
            st.components.v1.html(st.session_state.current_report_content, height=400, scrolling=True)
        else: # Markdown
            st.markdown(st.session_state.current_report_content)
    else:
        st.info("Generate a report from the sidebar to see a preview.")
    
    st.markdown("---")
    st.markdown(f"""<div style="text-align: center; font-size: small;"><p><strong>Disclaimer:</strong> This tool is for educational and experimental purposes. LLM outputs require expert verification. Always use responsibly.</p></div>""", unsafe_allow_html=True)


if __name__ == "__main__":
    # Initialize all session state keys
    for key, default_value in {
        'is_capturing': False,
        'raw_packet_data': [],
        'captured_packets_log': [],
        'llm_analysis_results': "",
        'alerts': [],
        'current_report_content': "",
        'packet_source_info': "N/A",
        'tshark_process': None, # Stores pyshark.LiveCapture object
        'live_capture_thread': None, # Stores the threading.Thread object
        'packets_in_live_capture': 0,
        'live_capture_interface': None, # Stores the selected interface for the thread
        'temp_capture_file': None, # Not used with pyshark directly for continuous sniff
        'temp_capture_file_for_processing': None, # Used for uploaded PCAPs
        'last_processed_pcap_path': None, # Path to the last PCAP file processed (uploaded or saved from live)
        'selected_packet_index': None,
        'current_prompt_template': "general_analysis",
        'nlp_suggested_filter': "",
        'nlp_interpretation_notes': "",
        'nlp_extracted_entities': {},
        'nlp_suggested_tshark_fields': [],
        'field_extraction_df': pd.DataFrame(),
        'nlp_command_history': deque(maxlen=NLP_HISTORY_LENGTH),
        'current_pcap_session_id': None,
        'pcap_save_dir': os.getcwd(),
        'manual_capture_filter_value': "",
        'active_capture_filter': "",
        'usr_q_add_in': "",
        'num_pkts_llm_in': 10,
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
        # LLM rate limiting
        'gemini_rate_limited_until': None,
        'mistral_rate_limited_until': None,
        'groq_rate_limited_until': None
    }.items():
        if key not in st.session_state:
            st.session_state[key] = default_value
    
    asyncio.run(main_ui())

```