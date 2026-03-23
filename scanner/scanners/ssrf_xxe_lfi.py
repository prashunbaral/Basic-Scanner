"""
SSRF, XXE, LFI, and Open Redirect vulnerability scanner
"""
import concurrent.futures
import re
import time
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from scanner.logger import logger
from scanner.utils import make_http_request, inject_payload, calculate_hash
from scanner.config import (
    SSRF_PAYLOADS, XXE_PAYLOADS, LFI_PAYLOADS, REDIRECT_PAYLOADS,
    MAX_WORKERS, TIMEOUT
)

class SSRFXXELFIScanner:
    """Detects SSRF, XXE, LFI, and Open Redirect vulnerabilities"""
    
    def __init__(self):
        self.findings = []
        self.tested_urls = set()
        logger.info("SSRFXXELFIScanner initialized")
    
    def scan_urls(self, urls: List[str]) -> List[Dict]:
        """
        Scan URLs for SSRF, XXE, LFI, and Open Redirect
        
        Args:
            urls: List of URLs to scan
        
        Returns:
            List of findings
        """
        logger.info(f"Starting SSRF/XXE/LFI/Redirect scan on {len(urls)} URLs")
        
        # Prepare test cases
        test_cases = self._prepare_test_cases(urls)
        logger.info(f"Testing {len(test_cases)} parameter instances")
        
        # Scan in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._test_parameter, tc['url'], tc['param'], tc['type']): tc
                for tc in test_cases
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    findings = future.result()
                    if findings:
                        self.findings.extend(findings)
                        for f in findings:
                            logger.info(f"[{f['type']}] Found: {f['url']}")
                except Exception as e:
                    logger.debug(f"Error during vulnerability test: {e}")
        
        logger.info(f"Scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    def _prepare_test_cases(self, urls: List[str]) -> List[Dict]:
        """Prepare test cases"""
        test_cases = []
        
        # Parameters that might be vulnerable to different attack types
        parameter_mapping = {
            'SSRF': ['url', 'uri', 'host', 'target', 'resource', 'fetch', 'download'],
            'XXE': ['xml', 'data', 'content', 'payload', 'message'],
            'LFI': ['file', 'path', 'dir', 'page', 'include', 'load'],
            'Redirect': ['url', 'redirect', 'return', 'target', 'next', 'dest', 'continue']
        }
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                
                for param_name in params.keys():
                    # Determine which tests to run based on parameter name
                    for vuln_type, param_list in parameter_mapping.items():
                        if any(p.lower() in param_name.lower() for p in param_list):
                            test_cases.append({
                                'url': url,
                                'param': param_name,
                                'type': vuln_type
                            })
                
                # Add generic tests if no parameters
                if not params:
                    for vuln_type in parameter_mapping.keys():
                        test_cases.append({
                            'url': url,
                            'param': parameter_mapping[vuln_type][0],
                            'type': vuln_type
                        })
            except:
                pass
        
        return test_cases[:2000]
    
    def _test_parameter(self, url: str, param: str, vuln_type: str) -> List[Dict]:
        """Test a parameter for vulnerabilities"""
        
        test_key = f"{url}:{param}:{vuln_type}"
        test_hash = calculate_hash(test_key)
        if test_hash in self.tested_urls:
            return []
        self.tested_urls.add(test_hash)
        
        findings = []
        
        try:
            if vuln_type == 'SSRF':
                finding = self._test_ssrf(url, param)
                if finding:
                    findings.append(finding)
            
            elif vuln_type == 'XXE':
                finding = self._test_xxe(url, param)
                if finding:
                    findings.append(finding)
            
            elif vuln_type == 'LFI':
                finding = self._test_lfi(url, param)
                if finding:
                    findings.append(finding)
            
            elif vuln_type == 'Redirect':
                finding = self._test_redirect(url, param)
                if finding:
                    findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error testing {vuln_type} on {url}:{param}: {e}")
        
        return findings
    
    def _test_ssrf(self, url: str, param: str) -> Dict or None:
        """Test for SSRF vulnerability"""
        
        for payload in SSRF_PAYLOADS:
            test_url = inject_payload(url, param, payload, method='query')
            
            try:
                response, status, error = make_http_request(test_url, timeout=TIMEOUT)
                
                if error or response is None:
                    continue
                
                # Check for signs of SSRF
                ssrf_indicators = [
                    '127.0.0.1',
                    'localhost',
                    'connection refused',
                    'timed out',
                    '169.254.169.254',  # AWS metadata
                ]
                
                for indicator in ssrf_indicators:
                    if indicator.lower() in response.lower():
                        finding = {
                            'type': 'SSRF',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'High',
                            'status_code': status,
                            'timestamp': time.time(),
                            'proof': f"Response contains: {indicator}"
                        }
                        return finding
            except:
                pass
        
        return None
    
    def _test_xxe(self, url: str, param: str) -> Dict or None:
        """Test for XXE vulnerability"""
        
        for payload in XXE_PAYLOADS:
            test_url = inject_payload(url, param, payload, method='query')
            
            try:
                response, status, error = make_http_request(test_url, timeout=TIMEOUT)
                
                if error or response is None:
                    continue
                
                # Check for XXE indicators
                xxe_indicators = [
                    'root:',
                    'bin:',
                    '/bin/bash',
                    'ENTITY',
                    '<!DOCTYPE',
                ]
                
                for indicator in xxe_indicators:
                    if indicator in response:
                        finding = {
                            'type': 'XXE',
                            'url': url,
                            'parameter': param,
                            'payload': payload[:100],
                            'severity': 'Critical',
                            'status_code': status,
                            'timestamp': time.time(),
                            'proof': f"XXE payload executed, response contains: {indicator}"
                        }
                        return finding
            except:
                pass
        
        return None
    
    def _test_lfi(self, url: str, param: str) -> Dict or None:
        """Test for Local File Inclusion"""
        
        for payload in LFI_PAYLOADS:
            test_url = inject_payload(url, param, payload, method='query')
            
            try:
                response, status, error = make_http_request(test_url, timeout=TIMEOUT)
                
                if error or response is None:
                    continue
                
                # Check for LFI indicators
                if status and status == 200:
                    lfi_indicators = [
                        'root:',
                        'bin:',
                        '/bin/bash',
                        'root:x:0:0',
                        'nologin',
                        'nobody:',
                    ]
                    
                    for indicator in lfi_indicators:
                        if indicator in response:
                            finding = {
                                'type': 'LFI',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'severity': 'Critical',
                                'status_code': status,
                                'timestamp': time.time(),
                                'proof': f"File inclusion successful, response contains: {indicator}"
                            }
                            return finding
            except:
                pass
        
        return None
    
    def _test_redirect(self, url: str, param: str) -> Dict or None:
        """Test for Open Redirect"""
        
        for payload in REDIRECT_PAYLOADS:
            test_url = inject_payload(url, param, payload, method='query')
            
            try:
                # Don't follow redirects to detect them
                response, status, error = make_http_request(test_url, timeout=TIMEOUT)
                
                if status and status in [301, 302, 303, 307, 308]:
                    finding = {
                        'type': 'Open Redirect',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'severity': 'Medium',
                        'status_code': status,
                        'timestamp': time.time(),
                        'proof': f"Redirect detected (status {status})"
                    }
                    return finding
            except:
                pass
        
        return None
    
    def get_findings_by_type(self) -> Dict[str, List[Dict]]:
        """Get findings organized by vulnerability type"""
        grouped = {}
        
        for finding in self.findings:
            vuln_type = finding.get('type', 'Unknown')
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(finding)
        
        return grouped

def scan_ssrf_xxe_lfi_redirect(urls: List[str]) -> List[Dict]:
    """Convenience function"""
    scanner = SSRFXXELFIScanner()
    return scanner.scan_urls(urls)
