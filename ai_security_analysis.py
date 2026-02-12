import json
import xml.etree.ElementTree as ET
import os
import requests

token = os.getenv("HF_API_TOKEN")
model = "tiiuae/falcon-7b-instruct"

summary = ""

# ZAP XML extract
if os.path.exists("zap.xml"):
    tree = ET.parse("zap.xml")
    root = tree.getroot()
    for alert in root.findall(".//alertitem"):
        summary += f"Vulnerability: {alert.findtext('alert')} - {alert.findtext('desc')}\n"

# Trivy JSON extract
if os.path.exists("trivy.json"):
    with open("trivy.json") as f:
        data = json.load(f)
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            summary += f"Vulnerability: {vuln['VulnerabilityID']} - {vuln['Description']}\n"

prompt = f"""You are a cybersecurity expert. Analyze these vulnerabilities and propose remediation steps.\n\n{summary}"""

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

api_url = f"https://api-inference.huggingface.co/models/{model}"

payload = {
    "inputs": prompt,
    "options": {"use_cache": False, "wait_for_model": True},
    "parameters": { "max_new_tokens": 500 }
}

response = requests.post(api_url, headers=headers, json=payload)
data = response.json()

with open("ai_security_recommendations.md", "w") as f:
    f.write(data[0]["generated_text"])
