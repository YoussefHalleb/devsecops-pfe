import json
import xml.etree.ElementTree as ET
import os
import requests

API_KEY = os.getenv("GEMINI_API_KEY")

summary = ""

# =====================
# DAST - OWASP ZAP
# =====================
if os.path.exists("zap.xml"):
    tree = ET.parse("zap.xml")
    root = tree.getroot()

    for alert in root.findall(".//alertitem"):
        summary += f"""
Vulnerability: {alert.findtext('alert')}
Risk: {alert.findtext('riskdesc')}
Description: {alert.findtext('desc')}
"""

# =====================
# SAST - TRIVY
# =====================
if os.path.exists("trivy.json"):
    with open("trivy.json") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            summary += f"""
Vulnerability: {vuln.get('VulnerabilityID')}
Severity: {vuln.get('Severity')}
Package: {vuln.get('PkgName')}
Description: {vuln.get('Description')}
"""

prompt = f"""
You are a senior DevSecOps and application security expert.

Analyze the following SAST and DAST vulnerabilities detected in a CI/CD pipeline.

For each vulnerability:
- Explain how it can be exploited
- Describe the technical and business impact
- Provide concrete remediation steps
- Give secure configuration or code examples
- Reference OWASP best practices when relevant

Vulnerabilities:
{summary}
"""

url = (
    "https://generativelanguage.googleapis.com/"
    "v1beta/models/gemini-pro:generateContent"
    f"?key={API_KEY}"
)

payload = {
    "contents": [
        {
            "parts": [
                {"text": prompt}
            ]
        }
    ]
}

response = requests.post(url, json=payload)
response.raise_for_status()

text = response.json()["candidates"][0]["content"]["parts"][0]["text"]

with open("ai_security_recommendations.md", "w") as f:
    f.write(text)

print("✅ Gemini security recommendations generated successfully.")
