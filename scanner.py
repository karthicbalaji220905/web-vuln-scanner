import requests
from bs4 import BeautifulSoup
import re
import time

def full_scan(url):
    results = {
        "target": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Security Headers Check
        security_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 
                           'Content-Security-Policy', 'X-XSS-Protection']
        missing_headers = [h for h in security_headers if h not in response.headers]
        
        if missing_headers:
            results["vulnerabilities"].append({
                "name": "Missing Security Headers",
                "severity": "Medium",
                "description": f"Missing headers: {', '.join(missing_headers)}",
                "recommendation": "Add proper security headers."
            })
            results["summary"]["medium"] += 1
        
        # Check for forms (potential XSS/SQLi points)
        forms = soup.find_all('form')
        if forms:
            results["vulnerabilities"].append({
                "name": "Form Detected",
                "severity": "Low",
                "description": f"Found {len(forms)} form(s) - potential input validation issues",
                "recommendation": "Ensure proper input sanitization."
            })
            results["summary"]["low"] += 1
        
        # Simulated XSS check
        if re.search(r'[<>\'"]', response.text):
            results["vulnerabilities"].append({
                "name": "Potential XSS Vector",
                "severity": "Medium",
                "description": "Page may be vulnerable to reflected XSS",
                "recommendation": "Implement output encoding."
            })
            results["summary"]["medium"] += 1
        
    except Exception as e:
        results["vulnerabilities"].append({
            "name": "Connection Error",
            "severity": "High",
            "description": str(e),
            "recommendation": "Check URL and network connectivity."
        })
        results["summary"]["high"] += 1
    
    return results