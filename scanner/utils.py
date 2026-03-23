"""
Utility functions for the vulnerability discovery framework
"""
import subprocess
import hashlib
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Set, Dict, Optional, Tuple
from scanner.logger import logger
from scanner.config import REQUIRED_TOOLS, EXCLUDE_PATTERNS, MAX_RESPONSE_SIZE, TIMEOUT, MAX_RETRIES
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings when verify_ssl=False
urllib3.disable_warnings(InsecureRequestWarning)

def check_tool_exists(tool: str, command: str = None) -> bool:
    """Check if an external tool is installed and available"""
    if command is None:
        command = f"{tool} --help"
    
    try:
        subprocess.run(command.split(), capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False

def run_command(command: str, timeout: int = TIMEOUT, retry: bool = True) -> Tuple[bool, str, str]:
    """
    Execute an external command with retry logic
    
    Returns:
        (success, combined_output, error_msg)
        where combined_output is stdout + stderr combined
    """
    attempts = 0
    last_error = None
    
    # Handle None timeout (run indefinitely)
    actual_timeout = timeout if timeout is not None else 86400  # 24 hours as fallback
    
    while attempts < MAX_RETRIES:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=actual_timeout,
                text=True
            )
            
            # Combine stdout and stderr since many tools output important info to stderr
            combined_output = result.stdout + result.stderr
            
            if result.returncode == 0 or combined_output:  # Success if returncode 0 or we got output
                return True, combined_output, ""
            else:
                last_error = result.stderr or "Command failed"
                attempts += 1
                if retry:
                    time.sleep(2 ** attempts)  # Exponential backoff
        except subprocess.TimeoutExpired:
            last_error = f"Command timeout ({actual_timeout}s)"
            attempts += 1
        except Exception as e:
            last_error = str(e)
            attempts += 1
    
    return False, "", last_error

def normalize_url(url: str) -> str:
    """Normalize and clean a URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove fragments
    url = url.split('#')[0]
    
    return url.rstrip('/')

def get_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def deduplicate_urls(urls: List[str]) -> Set[str]:
    """Deduplicate URLs while preserving order (convert to set)"""
    return set(normalize_url(url) for url in urls if url)

def filter_urls(urls: List[str]) -> List[str]:
    """Filter out unwanted URLs (static assets, etc.)"""
    filtered = []
    for url in urls:
        skip = False
        for pattern in EXCLUDE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                skip = True
                break
        
        if not skip:
            filtered.append(url)
    
    return filtered

def extract_parameters(url: str) -> Dict[str, str]:
    """Extract query parameters from URL"""
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def inject_payload(url: str, param: str, payload: str, method: str = 'query') -> str:
    """
    Inject a payload into a parameter
    
    Args:
        url: Target URL
        param: Parameter name
        payload: Payload to inject
        method: 'query' for GET parameters, 'path' for path parameter
    
    Returns:
        Modified URL with injected payload
    """
    parsed = urlparse(url)
    
    if method == 'query':
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Check if parameter exists
        param_found = False
        for key in list(params.keys()):
            if key.lower() == param.lower():
                params[key] = [payload]
                param_found = True
                break
        
        # If parameter doesn't exist, ADD it (for discovered parameters)
        if not param_found:
            params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    
    return url

def make_http_request(url: str, method: str = 'GET', data: Dict = None, timeout: int = TIMEOUT, verify_ssl: bool = True) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Make an HTTP request with error handling
    
    Returns:
        (response_body, status_code, error_message)
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        if method.upper() == 'GET':
            resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        else:
            resp = requests.post(url, data=data, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        
        # Limit response size
        if len(resp.text) > MAX_RESPONSE_SIZE * 1024 * 1024:
            logger.warning(f"Response too large: {len(resp.text)} bytes")
            return resp.text[:MAX_RESPONSE_SIZE * 1024 * 1024], resp.status_code, None
        
        return resp.text, resp.status_code, None
        
    except requests.Timeout:
        return None, None, "Request timeout"
    except requests.ConnectionError as e:
        return None, None, f"Connection error: {e}"
    except Exception as e:
        return None, None, str(e)

def detect_reflection(original_url: str, payload: str, response: str) -> bool:
    """
    Detect if payload is reflected in response
    
    Returns True if payload appears in response (indicates potential XSS)
    """
    if response is None:
        return False
    
    # Check for exact reflection
    if payload in response:
        return True
    
    # Check for HTML-encoded reflection
    import html
    encoded_payload = html.escape(payload)
    if encoded_payload in response:
        return True
    
    # Check for URL-encoded reflection
    from urllib.parse import quote
    url_encoded = quote(payload)
    if url_encoded in response:
        return True
    
    return False

def generate_xss_poc(url: str, param: str, payload: str) -> str:
    """Generate a clickable PoC URL for XSS"""
    # Use a simple alert payload that's easy to verify
    poc_payload = '"><script>alert("XSS Vulnerability Confirmed")</script>'
    return inject_payload(url, param, poc_payload, method='query')

def calculate_hash(data: str) -> str:
    """Calculate SHA256 hash of data"""
    return hashlib.sha256(data.encode()).hexdigest()

def is_valid_url(url: str) -> bool:
    """Validate if string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def sanitize_path(path: str) -> str:
    """Sanitize file path to prevent directory traversal"""
    # Remove any path traversal sequences
    path = re.sub(r'\.\./', '', path)
    path = re.sub(r'\.\.\\', '', path)
    return path

def get_unique_endpoints(urls: List[str]) -> Set[str]:
    """Extract unique endpoint paths from URLs"""
    endpoints = set()
    for url in urls:
        parsed = urlparse(url)
        # Combine path with first-level query param keys
        endpoint = parsed.path
        if parsed.query:
            first_param = parse_qs(parsed.query).keys()
            if first_param:
                endpoint = f"{endpoint}?{list(first_param)[0]}="
        endpoints.add(endpoint)
    return endpoints

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def merge_findings(findings_list: List[List[Dict]]) -> List[Dict]:
    """Merge multiple finding lists and deduplicate"""
    seen = set()
    merged = []
    
    for findings in findings_list:
        for finding in findings:
            # Create unique key based on type, URL, and parameter
            key = f"{finding.get('type', '')}:{finding.get('url', '')}:{finding.get('parameter', '')}"
            key_hash = calculate_hash(key)
            
            if key_hash not in seen:
                seen.add(key_hash)
                merged.append(finding)
    
    return merged

def validate_finding(finding: Dict) -> bool:
    """Validate that a finding has all required fields"""
    required_fields = ['type', 'url', 'severity', 'timestamp']
    return all(field in finding for field in required_fields)
