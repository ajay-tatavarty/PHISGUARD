import os
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import re
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# File handler with rotation
file_handler = RotatingFileHandler('app.log', maxBytes=10*1024*1024, backupCount=5)
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# Add handlers to logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def scan_url_virustotal(url: str) -> dict:
    """Scan URL using VirusTotal API."""
    logger.info(f"Starting VirusTotal scan for URL: {url}")
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        # Submit URL for scanning
        logger.debug("Sending VirusTotal URL scan request")
        scan_response = requests.post(
            f"{VIRUSTOTAL_API_URL}urls",
            headers=headers,
            data={"url": url}
        )
        
        if scan_response.status_code != 200:
            logger.error(f"VirusTotal scan request failed: Status {scan_response.status_code}, Response: {scan_response.text}")
            return {"error": "VirusTotal scan failed", "status_code": scan_response.status_code}

        scan_data = scan_response.json()
        analysis_id = scan_data["data"]["id"]
        logger.debug(f"VirusTotal scan submitted, analysis ID: {analysis_id}")

        # Get analysis results
        logger.debug("Fetching VirusTotal analysis results")
        analysis_response = requests.get(
            f"{VIRUSTOTAL_API_URL}analyses/{analysis_id}",
            headers=headers
        )
        
        if analysis_response.status_code != 200:
            logger.error(f"VirusTotal analysis request failed: Status {analysis_response.status_code}, Response: {analysis_response.text}")
            return {"error": "VirusTotal analysis failed", "status_code": analysis_response.status_code}

        results = analysis_response.json()
        stats = results["data"]["attributes"]["stats"]
        risk_score = calculate_risk_score(stats)
        logger.info(f"VirusTotal scan completed: Risk score {risk_score}, Suspicious: {risk_score > 30}")
        
        return {
            "url": url,
            "stats": stats,
            "risk_score": risk_score,
            "is_suspicious": risk_score > 30
        }
    except Exception as e:
        logger.error(f"Unexpected error during VirusTotal scan: {str(e)}")
        return {"error": str(e)}

def calculate_risk_score(stats: dict) -> float:
    """Calculate risk score based on VirusTotal stats."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    
    if total == 0:
        return 0.0
    
    # Weighted scoring: malicious has higher weight
    score = ((malicious * 0.7) + (suspicious * 0.3)) / total * 100
    return round(score, 2)

def analyze_with_gemini(url: str, virustotal_results: dict) -> dict:
    """Analyze URL content with Gemini API for enhanced analysis."""
    logger.info(f"Starting Gemini analysis for URL: {url}")
    try:
        # Fetch webpage content
        logger.debug("Fetching webpage content for Gemini analysis")
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            logger.error(f"Failed to fetch webpage content: Status {response.status_code}")
            return {"error": "Failed to fetch webpage content"}
        
        content = response.text[:10000]  # Limit content size
        logger.debug("Webpage content fetched successfully")
        
        prompt = f"""
        Analyze the following webpage content for phishing indicators:
        - Suspicious keywords (login, password, verify)
        - Mismatched branding
        - Urgent language
        - Suspicious links or forms
        
        VirusTotal results: {virustotal_results}
        Webpage content: {content[:2000]}
        
        Provide a detailed analysis and phishing probability (0-100).
        """
        
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        # Make request to Gemini API
        logger.debug("Sending Gemini API request")
        gemini_response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers,
            json=payload
        )
        
        if gemini_response.status_code != 200:
            logger.error(f"Gemini API request failed: Status {gemini_response.status_code}, Response: {gemini_response.text}")
            return {"error": "Gemini API failed", "status_code": gemini_response.status_code}
        
        result = gemini_response.json()
        analysis_text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        logger.info("Gemini analysis completed successfully")
        
        return {
            "gemini_analysis": analysis_text,
            "phishing_probability": extract_probability(analysis_text)
        }
    except Exception as e:
        logger.error(f"Unexpected error during Gemini analysis: {str(e)}")
        return {"error": str(e)}

def extract_probability(text: str) -> float:
    """Extract phishing probability from Gemini response."""
    match = re.search(r"phishing probability.*?(\d{1,3})", text, re.IGNORECASE)
    probability = float(match.group(1)) if match else 50.0
    logger.debug(f"Extracted phishing probability: {probability}")
    return probability

@app.route("/api/scan", methods=["POST"])
def scan_url():
    """API endpoint to scan a URL for phishing."""
    logger.info("Received /api/scan request")
    
    data = request.get_json()
    url = data.get("url")
    
    if not url:
        logger.error("Request failed: No URL provided in request body")
        return jsonify({"error": "URL is required"}), 400
    
    # Step 1: Scan with VirusTotal
    vt_results = scan_url_virustotal(url)
    
    if "error" in vt_results:
        return jsonify(vt_results), 500
    
    # Step 2: If suspicious, analyze with Gemini
    combined_results = vt_results
    if vt_results.get("is_suspicious"):
        logger.info("VirusTotal flagged URL as suspicious, triggering Gemini analysis")
        gemini_results = analyze_with_gemini(url, vt_results)
        combined_results.update(gemini_results)
    
    logger.info("Scan completed successfully")
    return jsonify(combined_results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)