import streamlit as st
import requests

# Configure page display
st.set_page_config(page_title="Project Hookline", page_icon="🛡️", layout="centered")

st.title("🛡️ Project Hookline")
st.subheader("Automated L1 SOC Email Triage Dashboard")
st.markdown("---")

# File upload component
uploaded_file = st.file_uploader("Drop a suspicious .eml file here", type=["eml"])

if uploaded_file is not None:
    if st.button("Run AI Forensics", type="primary"):
        with st.spinner("Analyzing headers, checking authentication, and triaging with Gemini..."):
            
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "message/rfc822")}
            try:
                response = requests.post("http://127.0.0.1:8002/api/v1/analyze-email", files=files)
                response.raise_for_status()
                data = response.json()
                
                verdict = data.get("verdict", {})
                auth = data.get("authentication", {})
                extracted = data.get("extracted_data", {})
                
                # --- CREATE TABS ---
                tab1, tab2, tab3 = st.tabs(["🤖 AI Analyst Summary", "📋 Forensic Details", "💻 Raw JSON Ledger"])
                
                # TAB 1: AI Verdict
                with tab1:
                    severity = verdict.get("severity", "Unknown")
                    if severity in ["Informational", "Low"]:
                        st.success(f"**Severity Level:** {severity}")
                    elif severity == "Medium":
                        st.warning(f"**Severity Level:** {severity}")
                    else:
                        st.error(f"**Severity Level:** {severity}")
                    
                    st.markdown(f"**Estimated Intent:** {verdict.get('intent', 'N/A')}")
                    st.markdown(f"**MITRE ATT&CK Tactic:** {verdict.get('mitre_tactic', 'N/A')}")
                    st.info(verdict.get("plain_english_summary", "No summary provided."))
                
                # TAB 2: Technical Breakdown
                with tab2:
                    st.header("📧 Email Metadata")
                    st.markdown(f"**Subject:** {extracted.get('subject', 'Unknown')}")
                    st.markdown(f"**Sender:** {extracted.get('sender', 'Unknown')}")
                    st.markdown(f"**Attachments:** {extracted.get('attachment_count', 0)} files")
                    
                    st.markdown("---")
                    
                    st.header("🔐 Sender Verification")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("SPF Record", "PASS" if auth.get("spf_record_present") else "FAIL")
                    col2.metric("DKIM Signature", "PASS" if auth.get("dkim_signature_valid") else "FAIL")
                    col3.metric("DMARC Record", "PASS" if auth.get("dmarc_record_present") else "FAIL")
                    
                    if auth.get("likely_spoofed"):
                        st.error("⚠️ WARNING: Cryptographic checks failed. The sender address is likely spoofed.")
                    else:
                        st.success("✅ Sender domain authenticity cryptographically verified.")
                
                # TAB 3: Raw JSON Data
                with tab3:
                    st.header("💻 Raw API Payload")
                    st.caption("Expand the nodes below to investigate the raw extracted indicators and metadata.")
                    st.json(data)
                
            except requests.exceptions.ConnectionError:
                st.error("Could not reach backend API. Ensure Uvicorn is active on port 8002.")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}")