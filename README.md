
Markdown

# 🛡️ Project Hookline: Automated L1 SOC Email Triage

An automated, AI-driven forensic analysis pipeline and dashboard designed to streamline Level 1 Security Operations Center (SOC) email triage. Project Hookline safely ingests raw `.eml` files, extracts forensic indicators, validates sender authenticity, and leverages Google Gemini to generate immediate, structured triage verdicts.

## ✨ Key Features

* **📩 Safe MIME Parsing:** Cracks open `.eml` structures to extract subjects, senders, headers, and raw body parts without executing malicious payloads.
* **🔐 Cryptographic Sender Validation:** Performs live DNS lookups to validate SPF, DKIM, and DMARC records to detect domain spoofing.
* **🔍 Deterministic IOC Extraction:** Scans headers and email bodies using regex to extract IP addresses, URLs, and secure SHA-256 hashes of attachments.
* **🤖 AI Triage Agent:** Utilizes **Gemini 2.5 Flash** (structured with Pydantic) to synthesize forensic data into a definitive verdict, assigning severity, threat intent, and MITRE ATT&CK tactics.
* **📊 L1/L2 Streamlit Dashboard:** An interactive, multi-tab frontend providing an executive AI summary for L1 analysts and a raw JSON data ledger for L2 incident responders.

## 🛠️ Tech Stack

* **Backend API:** FastAPI, Uvicorn, Python
* **Frontend Dashboard:** Streamlit
* **AI & Validation:** Google GenAI SDK (Gemini 2.5 Flash), Pydantic
* **Forensics:** `dnspython`, `dkimpy`

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone [https://github.com/josephtran27/project-hookline.git](https://github.com/josephtran27/project-hookline.git)
cd project-hookline
2. Set Up the Environment
Create a virtual environment and install the dependencies:
Bash

python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
3. Configure API Keys
Create a .env file in the root directory and add your Gemini API key:
Code snippet

GEMINI_API_KEY=your_gemini_api_key_here
4. Launch the Application
Project Hookline requires two terminal windows to run both the backend API and the frontend dashboard simultaneously.
Terminal 1: Start the FastAPI Backend
Bash

source .venv/bin/activate
python -m uvicorn app.main:app --reload --reload-dir app --port 8002
The API documentation will be available at http://127.0.0.1:8002/docs
Terminal 2: Start the Streamlit Dashboard
Bash

source .venv/bin/activate
streamlit run app/dashboard.py
The dashboard will automatically open in your browser at http://localhost:8501
🗺️ Roadmap
* [x] Core MIME Parsing & Forensics Engine
* [x] Threat Intel IOC Extraction
* [x] Gemini AI Triage Integration
* [x] Interactive Streamlit Dashboard
* [ ] Supabase Ledger Integration for Persistent Storage
* [ ] Automated Slack Webhook Alerts for High-Severity Threats
