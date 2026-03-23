"""
XSS (Cross-Site Scripting) vulnerability scanner
Detects reflected and stored XSS vulnerabilities
"""
import concurrent.futures
import re
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse, parse_qs
from scanner.logger import logger
from scanner.utils import (
    make_http_request, inject_payload, detect_reflection,
    generate_xss_poc, calculate_hash, get_unique_endpoints
)
from scanner.config import XSS_PAYLOADS, XSS_DETECTION, MAX_WORKERS, TIMEOUT
import time

class XSSScanner:
    """Detects reflected and potential stored XSS vulnerabilities"""
    
    def __init__(self):
        self.findings = []
        self.tested_urls = set()
        logger.info("XSSScanner initialized")
    
    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """
        Scan URLs for XSS vulnerabilities
        
        Args:
            urls: List of URLs to scan
        
        Returns:
            List of XSS findings
        """
        logger.info(f"Starting XSS scan on {len(urls)} URLs")
        
        # Extract parameters and test
        test_cases = self._prepare_test_cases(urls)
        
        logger.info(f"Testing {len(test_cases)} parameter instances")
        
        # Scan in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._test_url_parameter, tc['url'], tc['param'], tc.get('value')): tc 
                for tc in test_cases
            }
            
            for future in concurrent.futures.as_completed(futures):
                test_case = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        self.findings.append(finding)
                        logger.info(f"[XSS] Found vulnerability in {finding['url']}")
                except Exception as e:
                    logger.debug(f"Error testing {test_case['url']}: {e}")
        
        logger.info(f"XSS scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    def _prepare_test_cases(self, urls: List[str]) -> List[Dict]:
        """Prepare test cases from URLs"""
        test_cases = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                
                for param_name in params.keys():
                    test_cases.append({
                        'url': url,
                        'param': param_name,
                        'value': params[param_name][0] if params[param_name] else ''
                    })
                
                # Also add URLs with no parameters for testing
                if not params:
                    # Try to detect parameter names from path
                    potential_params = ['id', 'q', 'search', 'name', 'user', 'msg', 'message', 'text']
                    for param in potential_params:
                        test_cases.append({
                            'url': url,
                            'param': param,
                            'value': ''
                        })
            except:
                pass
        
        return test_cases[:1000]  # Limit to 1000 test cases
    
    def _test_url_parameter(self, url: str, param: str, current_value: str = '') -> Dict or None:
        """Test a single parameter for XSS"""
        
        # Skip if already tested
        test_key = f"{url}:{param}"
        test_hash = calculate_hash(test_key)
        if test_hash in self.tested_urls:
            return None
        self.tested_urls.add(test_hash)
        
        try:
            # Test with each payload
            for payload_name, payload in XSS_PAYLOADS.items():
                test_url = inject_payload(url, param, payload, method='query')
                
                # Make request
                response, status, error = make_http_request(test_url, timeout=TIMEOUT)
                
                if error or response is None:
                    continue
                
                # Check for reflection
                if detect_reflection(test_url, payload, response):
                    # Verify it's actually XSS (not just string reflection)
                    if self._verify_xss(response, payload):
                        # Generate PoC
                        poc_url = generate_xss_poc(url, param, payload)
                        
                        finding = {
                            'type': 'XSS (Reflected)',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'payload_type': payload_name,
                            'poc_url': poc_url,
                            'severity': 'High',
                            'status_code': status,
                            'response_preview': response[:500],
                            'timestamp': time.time(),
                            'proof': f"Payload reflected in response: {payload[:50]}"
                        }
                        
                        return finding
        
        except Exception as e:
            logger.debug(f"Error testing {url}:{param}: {e}")
        
        return None
    
    def _verify_xss(self, response: str, payload: str) -> bool:
        """Verify that response indicates actual XSS (not just text reflection)"""
        
        # Check for dangerous patterns
        xss_indicators = [
            '<script',
            'onerror',
            'onload',
            'onclick',
            'onmouseover',
            'alert',
            'confirm',
            'prompt',
        ]
        
        for indicator in xss_indicators:
            if indicator.lower() in response.lower():
                return True
        
        return False
    
    def scan_stored_xss_sinks(self, sinks: Dict[str, List[str]]) -> List[Dict]:
        """
        Scan for potential stored XSS based on identified sinks
        
        Args:
            sinks: Dict of {url: [sink_patterns]}
        
        Returns:
            List of potential stored XSS findings
        """
        findings = []
        
        logger.info(f"Analyzing {len(sinks)} potential stored XSS sinks")
        
        for js_url, sink_list in sinks.items():
            if sink_list:
                finding = {
                    'type': 'XSS (Potential Stored)',
                    'url': js_url,
                    'severity': 'High',
                    'sinks': sink_list,
                    'timestamp': time.time(),
                    'parameter': 'N/A (JS sink)',
                    'proof': f"Found {len(sink_list)} potential XSS sink(s) in JavaScript"
                }
                findings.append(finding)
        
        logger.info(f"Found {len(findings)} potential stored XSS sinks")
        return findings
    
    def get_findings_summary(self) -> Dict:
        """Get summary of findings"""
        summary = {
            'total': len(self.findings),
            'by_severity': {},
            'by_type': {}
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown')
            xss_type = finding.get('type', 'Unknown')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][xss_type] = summary['by_type'].get(xss_type, 0) + 1
        
        return summary
    
    def get_poc_urls(self) -> List[str]:
        """Get list of PoC URLs for verified findings"""
        poc_urls = []
        for finding in self.findings:
            if 'poc_url' in finding:
                poc_urls.append(finding['poc_url'])
        return poc_urls

def scan_xss(urls: List[str]) -> List[Dict]:
    """Convenience function to scan for XSS"""
    scanner = XSSScanner()
    return scanner.scan_urls(urls)
