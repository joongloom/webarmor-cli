import requests
import re
import ssl
import socket
import json
import base64
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedSecurityAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.severity_scores = {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 5, 'LOW': 2, 'INFO': 1}
        self.lfi_payloads = ['../../../../etc/passwd', '..%5c..%5c..%5c..%5c/windows/win.ini']
        self.rce_payloads = ['; ls', '| dir', '`id`', '$(whoami)']
        self.xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        self.sqli_payloads = ["' OR 1=1-- -", "' UNION SELECT null,version()-- -"]

    def comprehensive_scan(self, url):
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'security_score': 100,
            'findings': []
        }

        try:
            basic_info = self.analyze_url(url)
            if 'error' in basic_info:
                return basic_info
            
            results.update(basic_info)
            
            self.check_ssl(url, results)
            self.check_headers(basic_info.get('headers', {}), results)
            self.check_cookies(basic_info.get('cookies', []), results)
            self.check_forms(basic_info.get('content', ''), results)
            self.check_vulns(url, basic_info.get('content', ''), results)
            
            self.calculate_score(results)
            
        except Exception as e:
            results['error'] = str(e)

        return results

    def analyze_url(self, url):
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'cookies': response.cookies,
                'content': response.text,
                'final_url': response.url
            }
        except Exception as e:
            return {'error': str(e)}

    def check_ssl(self, url, results):
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            results['findings'].append({'type': 'No HTTPS', 'severity': 'HIGH', 'desc': 'Site doesnt use HTTPS'})
            return

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cipher = ssock.cipher()
                    if 'RC4' in cipher[0] or 'MD5' in cipher[0]:
                        results['findings'].append({'type': 'Weak Cipher', 'severity': 'HIGH', 'desc': f'weak cypher: {cipher[0]}'})
        except:
            pass

    def check_headers(self, headers, results):
        required = {
            'Strict-Transport-Security': 'HIGH',
            'Content-Security-Policy': 'HIGH',
            'X-Frame-Options': 'MEDIUM',
            'X-Content-Type-Options': 'LOW'
        }
        for h, sev in required.items():
            if h not in headers:
                results['findings'].append({'type': 'Missing Header', 'severity': sev, 'desc': f'missing {h}'})

    def check_cookies(self, cookies, results):
        for c in cookies:
            if not c.secure:
                results['findings'].append({'type': 'Insecure Cookie', 'severity': 'MEDIUM', 'desc': f'Cookie {c.name} no Secure'})
            if not c.has_nonstandard_attr('HttpOnly'):
                results['findings'].append({'type': 'No HttpOnly', 'severity': 'MEDIUM', 'desc': f'Cookie {c.name} no HttpOnly'})

    def check_forms(self, content, results):
        soup = BeautifulSoup(content, 'html.parser')
        for form in soup.find_all('form'):
            if not form.find(['input'], {'name': re.compile(r'csrf|token', re.I)}):
                results['findings'].append({'type': 'CSRF Risk', 'severity': 'HIGH', 'desc': 'form without CSRF токена'})

    def check_vulns(self, url, content, results):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param, values in params.items():
            for val in values:
                for pl in self.sqli_payloads:
                    target = url.replace(f"{param}={val}", f"{param}={pl}")
                    try:
                        res = self.session.get(target, timeout=5, verify=False)
                        if "SQL" in res.text or "mysql" in res.text:
                            results['findings'].append({'type': 'SQL Injection', 'severity': 'CRITICAL', 'desc': f'SQLi in parametr {param}'})
                    except: pass
                
                for pl in self.xss_payloads:
                    target = url.replace(f"{param}={val}", f"{param}={pl}")
                    try:
                        res = self.session.get(target, timeout=5, verify=False)
                        if pl in res.text:
                            results['findings'].append({'type': 'XSS', 'severity': 'HIGH', 'desc': f'XSS in parameter {param}'})
                    except: pass

        for pl in self.lfi_payloads:
            target = f"{url.split('?')[0]}?page={pl}"
            try:
                res = self.session.get(target, timeout=5, verify=False)
                if "root:" in res.text:
                    results['findings'].append({'type': 'LFI', 'severity': 'CRITICAL', 'desc': f'LFI с payload {pl}'})
            except: pass

    def calculate_score(self, results):
        for f in results['findings']:
            results['security_score'] -= self.severity_scores.get(f['severity'], 1)
        results['security_score'] = max(0, results['security_score'])