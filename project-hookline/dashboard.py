import streamlit as st
import requests

# 1. Page Configuration
st.set_page_config(page_title="Hookline Triage Console", layout="wide", initial_sidebar_state="collapsed")

# 2. Inject Custom Enterprise CSS
st.markdown("""
<style>
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Layout padding */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* SIEM Metric Cards styling */
    div[data-testid="stMetric"] {
        background-color: #161A23;
        border: 1px solid #2D313A;
        padding: 15px 20px;
        border-radius: 8px;
        border-left: 4px solid #3b82f6;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    div[data-testid="stMetricValue"] {
        font-size: 1.6rem;
        font-weight: 700;
        color: #F8F9FA;
    }
    
    /* Sleek Custom Button */
    div.stButton > button:first-child {
        background-color: #0E1117;
        color: #3b82f6;
        border: 1px solid #3b82f6;
        border-radius: 6px;
        font-weight: 600;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
    }
    div.stButton > button:first-child:hover {
        background-color: #3b82f6;
        color: #ffffff;
        border: 1px solid #3b82f6;
        box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
    }
    
    /* Typography */
    h1 { font-weight: 700; font-size: 2.4rem; letter-spacing: -0.5px; }
    h3 { font-weight: 500; color: #9CA3AF; font-size: 1.2rem; }
</style>
""", unsafe_allow_html=True)

# 3. Header Section
st.title(":material/radar: Hookline Triage Console")
st.caption("L1 SOC Automated Ingestion & Forensic Analysis Engine")
st.divider()

# 4. Action Area
uploaded_file = st.file_uploader("Ingest .eml artifact for analysis", type=["eml"])

if uploaded_file is not None:
    if st.button(":material/memory: Execute Forensic Pipeline", type="primary"):
        with st.spinner("Ingesting artifact, extracting IOCs, and synthesizing threat intelligence..."):
            
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "message/rfc822")}
            try:
                response = requests.post("http://127.0.0.1:8002/api/v1/analyze-email", files=files)
                response.raise_for_status()
                data = response.json()
                
                verdict = data.get("verdict", {})
                auth = data.get("authentication", {})
                extracted = data.get("extracted_data", {})
                
                st.write("") 
                
                # --- CREATE TABS ---
                tab1, tab2, tab3 = st.tabs([
                    ":material/assignment: Executive Summary", 
                    ":material/policy: MIME Forensics & Auth", 
                    ":material/code: Raw Telemetry Ledger"
                ])
                
                # TAB 1: AI Verdict
                with tab1:
                    st.write("")
                    metric_col1, metric_col2, metric_col3 = st.columns(3)
                    
                    severity = verdict.get("severity", "Unknown")
                    metric_col1.metric("Assigned Severity", severity)
                    metric_col2.metric("Estimated Intent", verdict.get("intent", "N/A"))
                    metric_col3.metric("MITRE Tactic", verdict.get("mitre_tactic", "N/A"))
                    
                    st.write("")
                    
                    # Alert Box using native Streamlit alerts but with material icons
                    if severity in ["Informational", "Low"]:
                        st.success(f"**Analysis Conclusion:** {verdict.get('plain_english_summary', '')}", icon=":material/check_circle:")
                    elif severity == "Medium":
                        st.warning(f"**Analysis Conclusion:** {verdict.get('plain_english_summary', '')}", icon=":material/warning:")
                    else:
                        st.error(f"**Analysis Conclusion:** {verdict.get('plain_english_summary', '')}", icon=":material/gpp_bad:")
                
                # TAB 2: Technical Breakdown
                with tab2:
                    st.write("")
                    st.subheader("Artifact Metadata")
                    
                    # Using bordered containers for a cleaner look than disabled inputs
                    with st.container(border=True):
                        meta_c1, meta_c2 = st.columns(2)
                        with meta_c1:
                            st.markdown(f"**Subject Line:**\n{extracted.get('subject', 'Unknown')}")
                            st.markdown(f"**Sender Origin:**\n`{extracted.get('sender', 'Unknown')}`")
                        with meta_c2:
                            st.markdown(f"**Target Domain:**\n`{auth.get('domain_checked', 'Unknown')}`")
                            st.markdown(f"**Attachment Count:**\n{extracted.get('attachment_count', 0)}")
                    
                    st.write("")
                    st.subheader("Cryptographic Validation")
                    
                    auth_col1, auth_col2, auth_col3 = st.columns(3)
                    auth_col1.metric("SPF Record", "VALID" if auth.get("spf_record_present") else "INVALID")
                    auth_col2.metric("DKIM Signature", "VALID" if auth.get("dkim_signature_valid") else "INVALID")
                    auth_col3.metric("DMARC Record", "VALID" if auth.get("dmarc_record_present") else "INVALID")
                    
                    st.write("")
                    if auth.get("likely_spoofed"):
                        st.error("Authentication constraints failed. Domain spoofing detected.", icon=":material/dangerous:")
                    else:
                        st.info("Cryptographic signatures verified against authoritative DNS records.", icon=":material/verified_user:")
                
                # TAB 3: Raw JSON Data
                with tab3:
                    st.write("")
                    st.subheader("Pipeline Telemetry")
                    st.json(data)
                
            except requests.exceptions.ConnectionError:
                st.error("Connection Refused: Verify backend API is actively listening on port 8002.", icon=":material/wifi_off:")
            except Exception as e:
                st.error(f"Pipeline Exception: {e}", icon=":material/bug_report:")