import os
import json
import requests

HF_TOKEN = os.getenv("HF_API_TOKEN")
MODEL = "tiiuae/falcon-7b-instruct"
API_URL = f"https://api-inference.huggingface.co/models/{MODEL}"

headers = {
    "Authorization": f"Bearer {HF_TOKEN}",
    "Content-Type": "application/json"
}

summary = ""

# =====================
# TRIVY REPORT
# =====================
if os.path.exists("trivy.json"):
    with open("trivy.json") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            summary += f"""
Vulnerability ID: {vuln.get('VulnerabilityID')}
Severity: {vuln.get('Severity')}
Package: {vuln.get('PkgName')}
Description: {vuln.get('Description')}
"""

prompt = f"""
You are a cybersecurity expert.

Analyze the following vulnerabilities detected by Trivy.
For each vulnerability:
- Explain how it can be exploited
- Describe the security impact
- Provide concrete remediation steps
- Reference OWASP or security best practices

Vulnerabilities:
{summary}
"""

payload = {
    "inputs": prompt,
    "parameters": {
        "max_new_tokens": 600,
        "temperature": 0.2
    }
}

response = requests.post(API_URL, headers=headers, json=payload)
result = response.json()
print("HF RAW RESPONSE:")
print(result)


with open("ai_security_recommendations.md", "w") as f:
    if isinstance(result, list) and "generated_text" in result[0]:
        f.write(result[0]["generated_text"])
    else:
        f.write("AI analysis could not be generated. Please review the Trivy report manually.")

print("✅ AI security analysis completed (Trivy + Hugging Face).")
