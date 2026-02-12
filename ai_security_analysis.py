import json
import xml.etree.ElementTree as ET
import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2
)

with open("ai_security_recommendations.md", "w") as f:
    f.write(response.choices[0].message.content)

print("✅ OpenAI security recommendations generated successfully.")
