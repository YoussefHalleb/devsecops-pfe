import json
import os
import requests

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
API_URL = "https://api.groq.com/openai/v1/chat/completions"

headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

summary = ""
MAX_VULNS = 8
count = 0

# =====================
# TRIVY REPORT
# =====================
if os.path.exists("trivy.json"):
    with open("trivy.json") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if count >= MAX_VULNS:
                break

            summary += f"""
Vulnerability ID: {vuln.get('VulnerabilityID')}
Severity: {vuln.get('Severity')}
Package: {vuln.get('PkgName')}
Description: {vuln.get('Description')}
"""
            count += 1

prompt = f"""
You are a senior application security expert.

Analyze the following Trivy vulnerabilities.
For each vulnerability:
- Explain how it can be exploited
- Describe the impact
- Provide concrete remediation steps
- Reference OWASP best practices

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

# Debug utile
if response.status_code != 200:
    print("Groq RAW RESPONSE:")
    print(response.text)

response.raise_for_status()

result = response.json()

with open("ai_security_recommendations.md", "w") as f:
    f.write(result["choices"][0]["message"]["content"])

print("✅ AI security recommendations generated successfully using Groq (LLaMA 3.1).")
