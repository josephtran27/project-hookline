import os
import json
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# 1. Define the strict output structure using Pydantic
class TriageVerdict(BaseModel):
    severity: str = Field(description="One of: Informational, Low, Medium, High, Critical")
    intent: str = Field(description="The likely intent, e.g., Credential Harvesting, Malware Delivery, Spam, Legitimate Notification")
    mitre_tactic: str = Field(description="Relevant MITRE ATT&CK Tactic, or 'None' if safe")
    plain_english_summary: str = Field(description="A concise, 2-3 sentence explanation of the verdict based ONLY on the provided evidence")

async def analyze_incident_with_gemini(parsed_data: dict, auth_results: dict, enriched_iocs: dict) -> dict:
    """
    Feeds the collected evidence to Gemini 2.5 Flash and returns a structured JSON verdict.
    """
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your-gemini-api-key":
        return {
            "severity": "Unknown",
            "intent": "Unknown",
            "mitre_tactic": "Unknown",
            "plain_english_summary": "Gemini API key not configured. LLM analysis skipped."
        }

    # Initialize the async client
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    # 2. Construct the prompt with the deterministic evidence
    prompt = f"""
    You are an expert L1 SOC Analyst. Analyze the following email data and threat intelligence to determine if it is a phishing attack or safe.
    Do NOT invent or hallucinate indicators. Base your verdict strictly on the evidence below.

    --- EVIDENCE ---
    Subject: {parsed_data.get('subject')}
    Sender: {parsed_data.get('sender')}
    Body Text Extract: {parsed_data.get('body_plaintext')[:1500]} 

    Authentication Results:
    {json.dumps(auth_results, indent=2)}

    Threat Intelligence (IOCs):
    {json.dumps(enriched_iocs, indent=2)}
    -----------------
    """

    try:
        # 3. Call the API enforcing the Pydantic schema
        response = await client.aio.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=TriageVerdict,
                temperature=0.1, # Keep temperature low for analytical consistency
            ),
        )
        return json.loads(response.text)
    except Exception as e:
        return {
            "severity": "Error",
            "intent": "Error",
            "mitre_tactic": "Error",
            "plain_english_summary": f"Failed to generate LLM response: {str(e)}"
        }