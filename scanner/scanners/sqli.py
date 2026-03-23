"""
SQL Injection vulnerability scanner
Detects error-based, boolean-based, and time-based SQLi
"""
import concurrent.futures
import re
import time
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qs
from scanner.logger import logger
from scanner.utils import make_http_request, inject_payload, calculate_hash
from scanner.config import SQLI_PAYLOADS, SQLI_DETECTION, MAX_WORKERS, TIMEOUT
import requests

class SQLiScanner:
    """Detects SQL Injection vulnerabilities"""
    
    def __init__(self):
        self.findings = []
        self.tested_urls = set()
        self.baseline_responses = {}
        logger.info("SQLiScanner initialized")
    
    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """
        Scan URLs for SQL Injection vulnerabilities
        
        Args:
            urls: List of URLs to scan
        
        Returns:
            List of SQLi findings
        """
        logger.info(f"Starting SQL Injection scan on {len(urls)} URLs")
        
        # Prepare test cases
        test_cases = self._prepare_test_cases(urls)
        logger.info(f"Testing {len(test_cases)} parameter instances")
        
        # Scan in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._test_url_parameter, tc['url'], tc['param']): tc
                for tc in test_cases
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    finding = future.result()
                    if finding:
                        self.findings.append(finding)
                        logger.info(f"[SQLi] Found vulnerability: {finding['url']}")
                except Exception as e:
                    logger.debug(f"Error during SQLi test: {e}")
        
        logger.info(f"SQL Injection scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    def _prepare_test_cases(self, urls: List[str]) -> List[Dict]:
        """Prepare test cases from URLs"""
        test_cases = []
        
        # Common injectable parameters
        injectable_params = ['id', 'uid', 'user', 'name', 'email', 'search', 'q', 'query', 'filter']
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                
                for param_name in params.keys():
                    test_cases.append({
                        'url': url,
                        'param': param_name,
                    })
                
                # Add potential parameters not in URL
                if not params:
                    for param in injectable_params:
                        test_cases.append({
                            'url': url,
                            'param': param,
                        })
            except:
                pass
        
        return test_cases[:1000]
    
    def _test_url_parameter(self, url: str, param: str) -> Dict or None:
        """Test parameter for SQL Injection"""
        
        test_key = f"{url}:{param}"
        test_hash = calculate_hash(test_key)
        if test_hash in self.tested_urls:
            return None
        self.tested_urls.add(test_hash)
        
        try:
            # Get baseline response
            baseline_resp, baseline_status, _ = make_http_request(url, timeout=TIMEOUT)
            if baseline_resp is None:
                return None
            
            # Test error-based SQLi
            error_finding = self._test_error_based(url, param, baseline_resp)
            if error_finding:
                return error_finding
            
            # Test boolean-based SQLi
            bool_finding = self._test_boolean_based(url, param, baseline_resp)
            if bool_finding:
                return bool_finding
            
            # Test time-based SQLi
            time_finding = self._test_time_based(url, param)
            if time_finding:
                return time_finding
        
        except Exception as e:
            logger.debug(f"Error testing {url}:{param}: {e}")
        
        return None
    
    def _test_error_based(self, url: str, param: str, baseline_resp: str) -> Dict or None:
        """Test for error-based SQL Injection"""
        
        logger.debug(f"Testing error-based SQLi: {url}:{param}")
        
        for payload in SQLI_PAYLOADS.get('error_based', []):
            test_url = inject_payload(url, param, payload, method='query')
            
            try:
                response, status, _ = make_http_request(test_url, timeout=TIMEOUT)
                
                if response is None:
                    continue
                
                # Check for SQL error messages
                for error_indicator in SQLI_DETECTION:
                    if error_indicator.lower() in response.lower():
                        finding = {
                            'type': 'SQL Injection (Error-based)',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': 'error-based',
                            'severity': 'Critical',
                            'status_code': status,
                            'response_preview': response[:500],
                            'timestamp': time.time(),
                            'proof': f"SQL error message detected: {error_indicator}"
                        }
                        return finding
            except:
                pass
        
        return None
    
    def _test_boolean_based(self, url: str, param: str, baseline_resp: str) -> Dict or None:
        """Test for boolean-based SQL Injection"""
        
        logger.debug(f"Testing boolean-based SQLi: {url}:{param}")
        
        # Get true response
        true_payload = SQLI_PAYLOADS.get('boolean_based', [])[0] if SQLI_PAYLOADS.get('boolean_based') else "' AND '1'='1"
        true_url = inject_payload(url, param, true_payload, method='query')
        
        true_resp, _, _ = make_http_request(true_url, timeout=TIMEOUT)
        
        if true_resp is None:
            return None
        
        # Get false response
        false_payload = "' AND '1'='2"
        false_url = inject_payload(url, param, false_payload, method='query')
        
        false_resp, status, _ = make_http_request(false_url, timeout=TIMEOUT)
        
        if false_resp is None:
            return None
        
        # Compare responses
        baseline_len = len(baseline_resp)
        true_len = len(true_resp)
        false_len = len(false_resp)
        
        # If responses differ significantly, potential SQLi
        if abs(true_len - false_len) > 50 and abs(baseline_len - false_len) > 50:
            finding = {
                'type': 'SQL Injection (Boolean-based)',
                'url': url,
                'parameter': param,
                'payload': true_payload,
                'method': 'boolean-based',
                'severity': 'High',
                'status_code': status,
                'timestamp': time.time(),
                'proof': f"Response length changed: baseline={baseline_len}, true={true_len}, false={false_len}"
            }
            return finding
        
        return None
    
    def _test_time_based(self, url: str, param: str) -> Dict or None:
        """Test for time-based SQL Injection"""
        
        logger.debug(f"Testing time-based SQLi: {url}:{param}")
        
        # Test with SLEEP payload
        sleep_payload = "' AND SLEEP(5) -- -"
        test_url = inject_payload(url, param, sleep_payload, method='query')
        
        try:
            start_time = time.time()
            response, status, _ = make_http_request(test_url, timeout=10)
            elapsed = time.time() - start_time
            
            # If response took significantly longer, likely time-based SQLi
            if elapsed > 4:  # At least 4 seconds (accounting for network latency)
                finding = {
                    'type': 'SQL Injection (Time-based)',
                    'url': url,
                    'parameter': param,
                    'payload': sleep_payload,
                    'method': 'time-based',
                    'severity': 'High',
                    'status_code': status,
                    'timestamp': time.time(),
                    'proof': f"Response took {elapsed:.2f}s (expected delay: 5s)"
                }
                return finding
        except Exception as e:
            logger.debug(f"Time-based test timeout or error: {e}")
        
        return None
    
    def get_findings_summary(self) -> Dict:
        """Get summary of findings"""
        summary = {
            'total': len(self.findings),
            'by_method': {},
            'by_severity': {}
        }
        
        for finding in self.findings:
            method = finding.get('method', 'unknown')
            severity = finding.get('severity', 'unknown')
            
            summary['by_method'][method] = summary['by_method'].get(method, 0) + 1
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        return summary

def scan_sqli(urls: List[str]) -> List[Dict]:
    """Convenience function to scan for SQL Injection"""
    scanner = SQLiScanner()
    return scanner.scan_urls(urls)
