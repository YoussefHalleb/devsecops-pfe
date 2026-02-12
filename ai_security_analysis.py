import json
import os
import openai
import xml.etree.ElementTree as ET

openai.api_key = os.getenv("OPENAI_API_KEY")

summary = ""

# ======== DAST (ZAP XML) ========
try:
    tree = ET.parse("zap.xml")
    root = tree.getroot()

    for site in root.findall(".//site"):
        for alert in site.findall(".//alertitem"):
            name = alert.findtext("alert")
            risk = alert.findtext("riskdesc")
            desc = alert.findtext("desc")

            summary += f"""
Vulnerability: {name}
Risk: {risk}
Description: {desc}
"""
except Exception:
    summary += "\nNo ZAP report found.\n"

# ======== SAST (TRIVY JSON) ========
try:
    with open("trivy.json") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            summary += f"""
Vulnerability: {vuln['VulnerabilityID']}
Severity: {vuln['Severity']}
Package: {vuln['PkgName']}
Description: {vuln['Description']}
"""
except Exception:
    summary += "\nNo Trivy report found.\n"

# ======== PROMPT IA ========
prompt = f"""
You are a senior DevSecOps security expert.

Analyze the following SAST and DAST vulnerabilities.
For each vulnerability:
- Explain how it can be exploited
- Explain the business and technical impact
- Provide concrete remediation steps
- Give secure configuration or code examples if possible

Vulnerabilities:
{summary}
"""

response = openai.ChatCompletion.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2
)

with open("ai_security_recommendations.md", "w") as f:
    f.write(response.choices[0].message.content)

print("AI security recommendations generated.")
