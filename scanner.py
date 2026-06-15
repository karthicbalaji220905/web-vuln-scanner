import requests
from bs4 import BeautifulSoup
import re
import time
import urllib.parse
import ssl
import socket

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# ─────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────
def add_vuln(results, name, severity, description, recommendation, evidence=""):
    results["vulnerabilities"].append({
        "name": name,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence
    })
    results["summary"][severity.lower()] = results["summary"].get(severity.lower(), 0) + 1


# ─────────────────────────────────────────────────────────────
# 1. SECURITY HEADERS CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_security_headers(url, results):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        h = r.headers

        checks = {
            "Strict-Transport-Security": ("HSTS Missing", "High",
                "Site does not enforce HTTPS via HSTS header.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "X-Frame-Options": ("Clickjacking Risk", "Medium",
                "Site can be embedded in iframes - vulnerable to clickjacking.",
                "Add: X-Frame-Options: DENY or SAMEORIGIN"),
            "X-Content-Type-Options": ("MIME Sniffing Risk", "Low",
                "Browser may interpret files as different MIME types.",
                "Add: X-Content-Type-Options: nosniff"),
            "Content-Security-Policy": ("No CSP Header", "High",
                "No Content Security Policy - XSS attacks are easier.",
                "Add a Content-Security-Policy header to restrict sources."),
            "X-XSS-Protection": ("No XSS Protection Header", "Medium",
                "Browser-level XSS protection not enabled.",
                "Add: X-XSS-Protection: 1; mode=block"),
            "Referrer-Policy": ("No Referrer Policy", "Low",
                "Referrer information may leak to third parties.",
                "Add: Referrer-Policy: no-referrer-when-downgrade"),
            "Permissions-Policy": ("No Permissions Policy", "Low",
                "Browser features like camera/mic are not restricted.",
                "Add a Permissions-Policy header."),
        }

        for header, (name, severity, desc, rec) in checks.items():
            if header not in h:
                add_vuln(results, name, severity, desc, rec, f"Header '{header}' not found in response")

        # Check server version disclosure
        server = h.get("Server", "")
        if server and any(c.isdigit() for c in server):
            add_vuln(results, "Server Version Disclosure", "Medium",
                f"Server header reveals version: {server}",
                "Configure server to hide version info.",
                f"Server: {server}")

        # Check X-Powered-By
        powered = h.get("X-Powered-By", "")
        if powered:
            add_vuln(results, "Technology Disclosure", "Low",
                f"X-Powered-By header reveals tech stack: {powered}",
                "Remove X-Powered-By header from server config.",
                f"X-Powered-By: {powered}")

    except Exception as e:
        add_vuln(results, "Header Check Error", "Low", str(e), "Check connectivity.")


# ─────────────────────────────────────────────────────────────
# 2. SSL/TLS CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_ssl(url, results):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname

        if not url.startswith("https"):
            add_vuln(results, "No HTTPS", "Critical",
                "Site does not use HTTPS - data is transmitted in plaintext.",
                "Install an SSL certificate and redirect HTTP to HTTPS.",
                f"URL uses HTTP: {url}")
            return

        # Check SSL certificate
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                # Check expiry
                expire_str = cert.get('notAfter', '')
                if expire_str:
                    from datetime import datetime
                    expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 30:
                        add_vuln(results, "SSL Certificate Expiring Soon", "High",
                            f"SSL certificate expires in {days_left} days.",
                            "Renew the SSL certificate immediately.",
                            f"Expires: {expire_str}")

                # Check weak protocol
                if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    add_vuln(results, "Weak SSL/TLS Protocol", "High",
                        f"Server uses outdated protocol: {protocol}",
                        "Upgrade to TLS 1.2 or TLS 1.3.",
                        f"Protocol: {protocol}")

    except ssl.SSLCertVerificationError as e:
        add_vuln(results, "Invalid SSL Certificate", "Critical",
            "SSL certificate is invalid or self-signed.",
            "Install a valid SSL certificate from a trusted CA.",
            str(e))
    except Exception as e:
        pass


# ─────────────────────────────────────────────────────────────
# 3. XSS CHECK (Real - tests actual form inputs)
# ─────────────────────────────────────────────────────────────
def check_xss(url, results):
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
    ]

    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        vulnerable_forms = []

        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            if not action.startswith('http'):
                action = urllib.parse.urljoin(url, action)

            inputs = form.find_all('input')
            for payload in XSS_PAYLOADS:
                data = {}
                for inp in inputs:
                    name = inp.get('name', '')
                    if name:
                        data[name] = payload

                try:
                    if method == 'post':
                        resp = requests.post(action, data=data, headers=HEADERS, timeout=8, verify=False)
                    else:
                        resp = requests.get(action, params=data, headers=HEADERS, timeout=8, verify=False)

                    if payload in resp.text:
                        vulnerable_forms.append(action)
                        break
                except:
                    continue

        if vulnerable_forms:
            add_vuln(results, "Reflected XSS Vulnerability", "Critical",
                f"XSS payload was reflected in response from {len(vulnerable_forms)} form(s).",
                "Sanitize and encode all user inputs. Use Content-Security-Policy.",
                f"Vulnerable endpoints: {', '.join(set(vulnerable_forms))}")

    except Exception as e:
        pass


# ─────────────────────────────────────────────────────────────
# 4. SQL INJECTION CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_sqli(url, results):
    SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\""]
    SQLI_ERRORS = [
        "sql syntax", "mysql_fetch", "ora-", "sqlite3", "pg_query",
        "syntax error", "unclosed quotation", "sqlstate", "odbc",
        "microsoft ole db", "invalid query", "division by zero"
    ]

    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        vulnerable = []

        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            if not action.startswith('http'):
                action = urllib.parse.urljoin(url, action)

            inputs = form.find_all('input')
            for payload in SQLI_PAYLOADS:
                data = {}
                for inp in inputs:
                    name = inp.get('name', '')
                    if name:
                        data[name] = payload
                try:
                    if method == 'post':
                        resp = requests.post(action, data=data, headers=HEADERS, timeout=8, verify=False)
                    else:
                        resp = requests.get(action, params=data, headers=HEADERS, timeout=8, verify=False)

                    resp_lower = resp.text.lower()
                    for error in SQLI_ERRORS:
                        if error in resp_lower:
                            vulnerable.append((action, error))
                            break
                except:
                    continue

        # Also test URL parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                try:
                    resp = requests.get(test_url, headers=HEADERS, timeout=8, verify=False)
                    for error in SQLI_ERRORS:
                        if error in resp.text.lower():
                            vulnerable.append((test_url, error))
                            break
                except:
                    continue

        if vulnerable:
            add_vuln(results, "SQL Injection Vulnerability", "Critical",
                f"SQL error messages detected after injection payloads in {len(vulnerable)} location(s).",
                "Use parameterized queries / prepared statements. Never concatenate user input in SQL.",
                f"Locations: {', '.join(set([v[0] for v in vulnerable]))}")

    except Exception as e:
        pass


# ─────────────────────────────────────────────────────────────
# 5. OPEN REDIRECT CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_open_redirect(url, results):
    REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'dest', 'destination']
    TEST_URL = 'https://evil.com'

    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in REDIRECT_PARAMS:
            test_params = {param: TEST_URL}
            test_url = url + ('&' if '?' in url else '?') + urllib.parse.urlencode(test_params)
            try:
                resp = requests.get(test_url, headers=HEADERS, timeout=8, verify=False, allow_redirects=False)
                location = resp.headers.get('Location', '')
                if TEST_URL in location:
                    add_vuln(results, "Open Redirect Vulnerability", "High",
                        f"Parameter '{param}' allows redirecting to external sites.",
                        "Validate and whitelist redirect URLs. Never use raw user input as redirect target.",
                        f"Test URL: {test_url}")
                    break
            except:
                continue
    except Exception as e:
        pass


# ─────────────────────────────────────────────────────────────
# 6. SENSITIVE FILES CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_sensitive_files(url, results):
    SENSITIVE_PATHS = [
        '/.env', '/config.php', '/wp-config.php', '/.git/config',
        '/admin', '/admin/', '/phpmyadmin', '/phpinfo.php',
        '/robots.txt', '/sitemap.xml', '/.htaccess',
        '/backup.zip', '/db.sql', '/config.yml', '/config.yaml',
        '/.DS_Store', '/web.config', '/server-status'
    ]

    base = urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
    found = []

    for path in SENSITIVE_PATHS:
        try:
            resp = requests.get(base + path, headers=HEADERS, timeout=6, verify=False)
            if resp.status_code == 200 and len(resp.text) > 10:
                found.append(f"{path} (HTTP {resp.status_code})")
        except:
            continue

    if found:
        add_vuln(results, "Sensitive Files Exposed", "Critical",
            f"Found {len(found)} sensitive/admin file(s) publicly accessible.",
            "Block access to sensitive files via server config. Remove unnecessary files.",
            "Found: " + ', '.join(found))


# ─────────────────────────────────────────────────────────────
# 7. COOKIE SECURITY CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_cookies(url, results):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        cookies = r.cookies

        insecure = []
        no_httponly = []
        no_samesite = []

        for cookie in cookies:
            if not cookie.secure:
                insecure.append(cookie.name)
            if not cookie.has_nonstandard_attr('HttpOnly'):
                no_httponly.append(cookie.name)
            if not cookie.has_nonstandard_attr('SameSite'):
                no_samesite.append(cookie.name)

        if insecure:
            add_vuln(results, "Insecure Cookies (No Secure Flag)", "High",
                f"Cookies without Secure flag can be sent over HTTP: {', '.join(insecure)}",
                "Set 'Secure' flag on all cookies.",
                f"Cookies: {', '.join(insecure)}")

        if no_httponly:
            add_vuln(results, "Cookies Missing HttpOnly Flag", "Medium",
                f"Cookies accessible via JavaScript - XSS can steal them: {', '.join(no_httponly)}",
                "Set 'HttpOnly' flag on all session cookies.",
                f"Cookies: {', '.join(no_httponly)}")

    except Exception as e:
        pass


# ─────────────────────────────────────────────────────────────
# 8. DIRECTORY LISTING CHECK (Real)
# ─────────────────────────────────────────────────────────────
def check_directory_listing(url, results):
    DIRS = ['/images/', '/uploads/', '/files/', '/assets/', '/static/', '/css/', '/js/']
    base = urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
    found = []

    for d in DIRS:
        try:
            resp = requests.get(base + d, headers=HEADERS, timeout=6, verify=False)
            if resp.status_code == 200 and ('index of' in resp.text.lower() or 'directory listing' in resp.text.lower()):
                found.append(d)
        except:
            continue

    if found:
        add_vuln(results, "Directory Listing Enabled", "Medium",
            f"Directory listing is enabled - attackers can browse files.",
            "Disable directory listing in server configuration.",
            f"Directories: {', '.join(found)}")


# ─────────────────────────────────────────────────────────────
# MAIN SCAN FUNCTION
# ─────────────────────────────────────────────────────────────
def full_scan(url):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = {
        "target": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
    }

    print(f"[*] Starting real scan on {url}")

    check_ssl(url, results)
    print("[*] SSL check done")

    check_security_headers(url, results)
    print("[*] Headers check done")

    check_cookies(url, results)
    print("[*] Cookie check done")

    check_sensitive_files(url, results)
    print("[*] Sensitive files check done")

    check_directory_listing(url, results)
    print("[*] Directory listing check done")

    check_open_redirect(url, results)
    print("[*] Open redirect check done")

    check_xss(url, results)
    print("[*] XSS check done")

    check_sqli(url, results)
    print("[*] SQLi check done")

    total = sum(results["summary"].values())
    results["total_issues"] = total
    print(f"[*] Scan complete. Found {total} issues.")

    return results
