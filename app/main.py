from app.auth_check import perform_auth_checks
from app.ioc_extractor import extract_all_iocs
from app.enrichment import enrich_all_iocs
from app.triage_agent import analyze_incident_with_gemini  # <-- Added Gemini triage agent
import email
from email.policy import default
from fastapi import FastAPI, File, UploadFile, HTTPException

app = FastAPI(title="Project Hookline API", version="1.0")

@app.post("/api/v1/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    """
    Ingests a raw .eml file, parses the MIME structure, extracts
    headers, bodies, and attachments safely, validates authentication,
    enriches IOCs, and generates an LLM triage verdict.
    """
    # 1. Validate the file type
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a .eml file.")

    # 2. Read the raw bytes into memory
    raw_bytes = await file.read()
    
    # 3. Parse the email structure
    msg = email.message_from_bytes(raw_bytes, policy=default)
    
    # 4. Extract Core Headers
    parsed_data = {
        "subject": msg.get("Subject", "(No Subject)"),
        "sender": msg.get("From", "Unknown Sender"),
        "recipient": msg.get("To", "Unknown Recipient"),
        "received_chain": msg.get_all("Received", []),
        "body_plaintext": "",
        "body_html": "",
        "attachments": []
    }

    # 5. Traverse the MIME parts
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))

        # Extract attachments
        if "attachment" in content_disposition:
            filename = part.get_filename()
            if filename:
                # Do NOT save to disk to prevent accidental detonation
                file_data = part.get_payload(decode=True)
                parsed_data["attachments"].append({
                    "filename": filename,
                    "size_bytes": len(file_data) if file_data else 0,
                    "raw_bytes": file_data
                })
        
        # Extract readable body (ignore attachments for this step)
        elif "attachment" not in content_disposition:
            if content_type == "text/plain":
                parsed_data["body_plaintext"] += part.get_payload(decode=True).decode(errors="ignore")
            elif content_type == "text/html":
                parsed_data["body_html"] += part.get_payload(decode=True).decode(errors="ignore")

    # 6. Run Sender Authentication Checks
    auth_results = perform_auth_checks(parsed_data["sender"], raw_bytes)

    # 7. Extract Indicators of Compromise (IOCs)
    iocs = extract_all_iocs(parsed_data)
    
    # 8. Enrich IOCs via Threat Intelligence APIs
    enriched_iocs = await enrich_all_iocs(iocs)

    # 9. Generate AI Triage Verdict using Gemini
    verdict = await analyze_incident_with_gemini(parsed_data, auth_results, enriched_iocs)
    
    return {
        "status": "success",
        "message": "Email analyzed successfully",
        "verdict": verdict,  # <-- Structured AI verdict front and center
        "authentication": auth_results,
        "extracted_iocs": enriched_iocs,
        "extracted_data": {
            "subject": parsed_data["subject"],
            "sender": parsed_data["sender"],
            "attachment_count": len(parsed_data["attachments"])
        }
    }