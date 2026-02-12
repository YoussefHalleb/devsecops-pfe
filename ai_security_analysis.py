import json
import os
import requests
import xml.etree.ElementTree as ET

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
API_URL = "https://api.groq.com/openai/v1/chat/completions"

headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

summary = ""
MAX_ITEMS = 6
count = 0

# =====================
# TRIVY (SAST / SCA)
# =====================
if os.path.exists("trivy.json"):
    with open("trivy.json") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if count >= MAX_ITEMS:
                break

            summary += f"""
[SAST - Trivy]
Vulnerability ID: {vuln.get('VulnerabilityID')}
Severity: {vuln.get('Severity')}
Package: {vuln.get('PkgName')}
Description: {vuln.get('Description')}
"""
            count += 1

# =====================
# ZAP (DAST)
# =====================
if os.path.exists("zap.xml"):
    tree = ET.parse("zap.xml")
    root = tree.getroot()

    for alert in root.findall(".//alertitem"):
        if count >= MAX_ITEMS * 2:
            break

        summary += f"""
[DAST - OWASP ZAP]
Vulnerability: {alert.findtext('alert')}
Risk: {alert.findtext('riskdesc')}
URL: {alert.findtext('uri')}
Description: {alert.findtext('desc')}
"""
        count += 1

prompt = f"""
You are a senior DevSecOps and application security expert.

Analyze the following SAST and DAST vulnerabilities detected in a CI/CD pipeline.

For EACH vulnerability:
- Explain how it can be exploited
- Describe the technical and business impact
- Provide concrete remediation steps
- Reference OWASP Top 10 or security best practices

Vulnerabilities:
{summary}
"""

payload = {
    "model": "llama-3.1-8b-instant",
    "messages": [
        {"role": "user", "content": prompt}
    ],
    "temperature": 0.2
}

response = requests.post(API_URL, headers=headers, json=payload)
response.raise_for_status()

result = response.json()

with open("ai_security_recommendations.md", "w") as f:
    f.write(result["choices"][0]["message"]["content"])

print("✅ AI security recommendations generated (Trivy + ZAP + Groq).")
