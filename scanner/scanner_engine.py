"""
Advanced scanner engine with sophisticated vulnerability detection
"""

import sys
import time
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.logger import logger
from scanner.utils import (
    make_http_request, inject_payload, get_domain_from_url,
    check_tool_exists, run_command, calculate_hash, normalize_url
)
from scanner.config import (
    XSS_PAYLOADS, SQLI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS, LFI_PAYLOADS,
    REDIRECT_PAYLOADS, TIMEOUT, MAX_WORKERS, PATH_XSS_PAYLOADS, CUSTOM_PARAM_PAYLOADS,
    CUSTOM_PARAM_NAMES
)
from scanner.scanners.xxe import XXEScanner
from scanner.playwright_spider import run_playwright_spider
import concurrent.futures


class VulnerabilityScanner:
    """Main vulnerability scanner engine"""
    
    def __init__(self, target_url: str, threads: int = 10, timeout: int = 0,
                 deep: bool = False, aggressive: bool = False, bypass_waf: bool = False,
                 verbose: bool = False, silent: bool = False, live_output: bool = False, xss_verbose: bool = False):
        self.target_url = normalize_url(target_url)
        self.threads = min(threads, MAX_WORKERS)
        # timeout=0 means unlimited
        self.timeout = None if timeout == 0 else timeout
        self.deep = deep
        self.aggressive = aggressive
        self.bypass_waf = bypass_waf
        self.verbose = verbose
        self.silent = silent
        self.live_output = live_output
        self.xss_verbose = xss_verbose
        self.findings = []
        self.tested = set()
        self.discovered_urls = []  # Store URLs discovered during parameter discovery
        self.scan_types = []  # Store scan types for nuclei tag filtering

        # In silent mode, suppress warning/info logs from scanner internals.
        if self.silent:
            logger.setLevel(logging.CRITICAL)

        if not silent:
            logger.info(f"Scanner initialized for: {self.target_url}")
            if deep:
                logger.info("⚡ Deep scanning mode enabled")
            if aggressive:
                logger.info("🔥 Aggressive mode enabled")
            if bypass_waf:
                logger.info("🔐 WAF bypass techniques enabled")
    
    def log_info(self, message: str):
        """Log info message only if not in silent mode"""
        if not self.silent:
            logger.info(message)
    
    def validate_environment(self) -> bool:
        """Validate that required tools are available"""
        logger.info("Validating environment...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("Python 3.8+ required")
            return False
        
        logger.info("✅ Python 3.8+")
        return True
    
    def scan(self, param: Optional[str] = None, scan_types: List[str] = None) -> List[Dict]:
        """
        Main scanning function
        
        Args:
            param: Specific parameter to test
            scan_types: Types of scans to perform
        
        Returns:
            List of findings
        """
        if not scan_types:
            scan_types = ['xss', 'sqli']
        
        # Store scan_types for use in nuclei scanning
        self.scan_types = scan_types
        self.findings = []
        
        # Extract parameters from URL
        parameters = self._extract_parameters()
        
        # Common parameters to always test
        common_params = ['id', 'q', 'search', 'name', 'email', 'message', 'xss', 'test', 'debug', 'param', 'value', 'input', 'data', 'payload', 'keyword', 'user', 'username', 'comment', 'callback', 'url', 'redirect', 'return', 'next', 'page', 'category', 'type', 'sort', 'filter', 'tag']
        
        # If no parameters in URL, try parameter discovery
        if not parameters and not param:
            if not self.silent:
                logger.warning("⚠️  No parameters found in URL, discovering from domain...")
            discovered = self._discover_parameters_with_tools()
            if discovered:
                # Merge discovered parameters with common parameters
                parameters = list(set(discovered + common_params))
                self.log_info(f"✓ Discovered {len(discovered)} parameters from domain, testing {len(parameters)} total with common defaults")
                
                # Test discovered URLs directly (if any were found during parameter discovery)
                if hasattr(self, 'discovered_urls') and self.discovered_urls and 'xss' in scan_types:
                    logger.info(f"🔗 Also testing {len(self.discovered_urls)} discovered URLs for XSS injection...")
            else:
                if not self.silent:
                    logger.warning("⚠️  No parameters discovered, using common defaults")
                parameters = common_params
        elif parameters:
            # Merge discovered parameters in URL with common parameters
            parameters = list(set(parameters + common_params))
        elif param:
            parameters = [param]
        
        logger.info(f"Testing {len(parameters)} parameter(s)")
        
        # Run custom payload-based scans
        if 'xss' in scan_types:
            self._scan_xss(parameters)
            
            # Test discovered URLs for XSS
            if hasattr(self, 'discovered_urls') and self.discovered_urls:
                self._test_discovered_urls_xss(self.discovered_urls)
        
        if 'sqli' in scan_types:
            self._scan_sqli(parameters)
        
        if 'ssrf' in scan_types:
            self._scan_ssrf(parameters)
        
        if 'xxe' in scan_types or self.aggressive:
            self._scan_xxe(parameters)
        
        # Run enhanced scanning methods
        if 'path-xss' in scan_types or self.deep:
            self._scan_path_based_xss()
        
        if 'custom-param' in scan_types or self.deep:
            self._scan_custom_parameters()
        
        if 'sqlmap' in scan_types or (self.deep and 'sqli' in scan_types):
            self._scan_sqli_with_sqlmap()
        
        # Additional parameter discovery in aggressive mode
        if self.aggressive and not param:
            additional_params = self._discover_parameters_with_tools()
            if additional_params:
                # Filter out already tested parameters
                new_params = [p for p in additional_params if p not in parameters]
                if new_params:
                    logger.info(f"✓ Testing {len(new_params)} additional discovered parameters")
                    if 'xss' in scan_types:
                        self._scan_xss(new_params)
                    if 'sqli' in scan_types:
                        self._scan_sqli(new_params)
                
                # Test discovered URLs directly
                if self.discovered_urls and 'xss' in scan_types:
                    logger.info(f"🔗 Testing {len(self.discovered_urls)} discovered URLs for XSS...")
                    self._test_discovered_urls_xss(self.discovered_urls)
        
        # Run Nuclei scanning when explicitly selected OR when XSS is being scanned
        if 'nuclei' in scan_types or 'xss' in scan_types:
            try:
                if self.deep:
                    self._scan_nuclei_advanced()
                else:
                    self._scan_nuclei()
            except Exception as e:
                logger.debug(f"Nuclei scanning skipped: {e}")
        
        return self.findings
    
    def _extract_parameters(self) -> List[str]:
        """Extract parameters from URL"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return list(params.keys())
    
    def _scan_xss(self, parameters: List[str]):
        """Advanced XSS scanning with marker injection or dangerous payloads based on mode"""
        self.log_info("🔍 [XSS] Starting XSS scan...")
        self.log_info(f"   Parameters to test: {parameters}")
        
        # In marker mode (default), only test for injectability without dangerous payloads
        if not self.xss_verbose:
            logger.info("📍 Using marker injection mode - testing for parameter reflection only")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                # Test each parameter once with marker
                for param in parameters:
                    future = executor.submit(self._test_xss, param, 'marker', '')
                    futures.append(future)
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            self.findings.append(result)
                            if self.live_output:
                                self._print_finding(result)
                    except Exception as e:
                        logger.debug(f"Error in XSS marker test: {e}")
            
            logger.info(f"✅ XSS marker injection scan complete")
            return
        
        # VERBOSE MODE: Use dangerous payloads
        logger.info("⚠️  XSS verbose mode - testing with dangerous payloads")
        payloads = XSS_PAYLOADS
        
        # If deep mode, use all payloads; otherwise, sample
        if not self.deep:
            # Use a smaller set for quick scanning
            priority_payloads = {
                'basic_script': XSS_PAYLOADS['basic_script'],
                'basic_img': XSS_PAYLOADS['basic_img'],
                'autofocus_event': XSS_PAYLOADS['autofocus_event'],
                'svg_onload': XSS_PAYLOADS['svg_onload'],
                'event_handlers': XSS_PAYLOADS['oninput'],
            }
            payloads = priority_payloads
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Single parameter testing
            for param in parameters:
                for payload_name, payload in payloads.items():
                    # Test single parameter with original payload
                    future = executor.submit(self._test_xss, param, payload_name, payload)
                    futures.append(future)
                    
                    # Test with multi-encoding variants
                    for encoding_variant in self._generate_encoding_variants(payload):
                        variant_name = f"{payload_name}_encoded"
                        future = executor.submit(self._test_xss, param, variant_name, encoding_variant)
                        futures.append(future)
            
            # Multi-parameter testing (if aggressive or deep)
            if self.aggressive or self.deep:
                if len(parameters) >= 2:
                    # Create combinations of parameters for simultaneous injection
                    for payload_name, payload in list(payloads.items())[:5]:  # Limit to top 5 for speed
                        future = executor.submit(
                            self._test_multi_param_xss, 
                            parameters, 
                            payload_name, 
                            payload
                        )
                        futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        if self.live_output:
                            self._print_finding(result)
                except Exception as e:
                    logger.debug(f"Error in XSS test: {e}")
        
        logger.info(f"✅ XSS scan complete")
    
    def _test_discovered_urls_xss(self, urls: List[str]):
        """Test discovered URLs for XSS by injecting markers into their parameters"""
        # Deduplicate while preserving order before exhaustive testing.
        unique_urls = list(dict.fromkeys(urls))
        logger.info(f"🔗 Testing {len(unique_urls)} discovered URLs for parameter injection...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Exhaustive mode: test every discovered URL.
            for url in unique_urls:
                try:
                    # Extract parameters from this URL
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    
                    if params:
                        # Test each parameter in its original URL context
                        for param_name in params.keys():
                            # Try marker variations on this specific URL
                            marker_variations = [
                                ('"><s>superman', 'tag_break'),
                                ('" superman', 'attribute_quote'),
                            ]
                            
                            for marker_payload, marker_type in marker_variations:
                                future = executor.submit(
                                    self._test_url_parameter_xss,
                                    url,
                                    param_name,
                                    marker_payload,
                                    marker_type
                                )
                                futures.append(future)
                
                except Exception as e:
                    logger.debug(f"Error processing discovered URL {url}: {e}")
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        if self.live_output:
                            self._print_finding(result)
                except Exception as e:
                    logger.debug(f"Error in discovered URL test: {e}")
        
        logger.info(f"✅ Discovered URLs XSS testing complete")
    
    def _test_url_parameter_xss(self, url: str, param: str, marker: str, marker_type: str) -> Optional[Dict]:
        """Test specific parameter in specific URL for XSS injection"""
        test_key = f"{url}:{param}:{marker_type}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            # Inject marker into this URL's parameter
            test_url = inject_payload(url, param, marker, method='query')
            response, status, error = make_http_request(
                test_url,
                timeout=self.timeout,
                verify_ssl=False
            )
            
            if response and self._is_marker_actually_reflected(marker, response, marker_type):
                # Found injectable parameter in discovered URL
                finding = {
                    'type': 'INJECTABLE',
                    'status': '[INJECTABLE]',
                    'url': url,
                    'test_url': test_url,
                    'parameter': param,
                    'payload': marker,
                    'payload_type': marker_type,
                    'severity': 'Medium',
                    'status_code': status,
                    'proof': f"Parameter reflects user input ({marker_type})",
                    'timestamp': time.time(),
                }
                
                logger.info(f"✅ [INJECTABLE] Found in discovered URL: {param} ({marker_type})")
                logger.info(f"    URL: {url}")
                return finding
        
        except Exception as e:
            logger.debug(f"Error testing URL parameter: {e}")
        
        return None
    
    def _test_xss(self, param: str, payload_name: str, payload: str) -> Optional[Dict]:
        """Test parameter for XSS with context-aware payload selection"""
        
        test_key = f"{param}:{payload_name}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            # CONTEXT-AWARE DETECTION MODE
            if not self.xss_verbose:
                # Step 1: Inject harmless marker to detect reflection context
                harmless_marker = "superman"
                marker_url = inject_payload(self.target_url, param, harmless_marker, method='query')
                
                marker_response, marker_status, marker_error = make_http_request(
                    marker_url,
                    timeout=self.timeout,
                    verify_ssl=False
                )
                
                if marker_error or not marker_response or harmless_marker not in marker_response:
                    # No reflection detected
                    return None
                
                # Step 2: Analyze context - where and how is the marker reflected?
                context = self._detect_reflection_context(param, harmless_marker, marker_response)
                
                # Step 3: Based on context, test with appropriate escape payloads
                if context == "html_attribute_double_quote":
                    # Escaping from HTML attribute with double quotes: " or "><
                    test_payloads = [
                        ('" superman', 'attribute_double_quote'),
                        ('"><s>superman', 'html_tag_break'),
                    ]
                elif context == "html_attribute_single_quote":
                    # Escaping from HTML attribute with single quotes: ' or '><
                    test_payloads = [
                        ("' superman", 'attribute_single_quote'),
                        ("'><s>superman", 'html_tag_break_single'),
                    ]
                elif context == "javascript_single_quote":
                    # Escaping from JavaScript single-quoted string: ';...;'
                    test_payloads = [
                        ("';alert(1);//", 'js_single_quote_escape'),
                        ("')+alert(1)+('", 'js_single_quote_break'),
                    ]
                elif context == "javascript_double_quote":
                    # Escaping from JavaScript double-quoted string: ";...;"
                    test_payloads = [
                        ('";alert(1);//', 'js_double_quote_escape'),
                        ('\")+alert(1)+(\"', 'js_double_quote_break'),
                    ]
                elif context == "javascript_unquoted":
                    # Unquoted JavaScript context
                    test_payloads = [
                        (')\nalert(1)\n//', 'js_unquoted_break'),
                    ]
                else:
                    # Unknown or other context - try basic escapes
                    test_payloads = [
                        ('"><s>superman', 'tag_break'),
                        ('" superman', 'attribute_quote'),
                        ("' superman", 'single_quote'),
                    ]
                
                # Step 4: Test with context-appropriate payloads
                for test_payload, test_type in test_payloads:
                    test_url = inject_payload(self.target_url, param, test_payload, method='query')
                    
                    test_response, test_status, test_error = make_http_request(
                        test_url,
                        timeout=self.timeout,
                        verify_ssl=False
                    )
                    
                    if test_error or not test_response:
                        continue
                    
                    # Check if escape payload is reflected
                    if test_payload in test_response:
                        # Verify it actually escapes the context
                        if self._is_marker_actually_reflected(test_payload, test_response, test_type):
                            finding = {
                                'type': 'INJECTABLE',
                                'status': '[INJECTABLE]',
                                'url': self.target_url,
                                'test_url': test_url,
                                'parameter': param,
                                'payload': test_payload,
                                'payload_type': test_type,
                                'context': context,
                                'severity': 'Medium',
                                'status_code': test_status,
                                'proof': f"Parameter injectable in {context} context",
                                'timestamp': time.time(),
                            }
                            
                            logger.info(f"✅ [INJECTABLE] Found in {context}: {param} ({test_type})")
                            logger.info(f"    URL: {test_url}")
                            return finding
                
                return None
            
            # VERBOSE MODE: Test with dangerous payloads (--xss-verbose)
            # Only activated when user provides complete URL with parameters
            test_url = inject_payload(self.target_url, param, payload, method='query')
            response, status, error = make_http_request(
                test_url, 
                timeout=self.timeout,
                verify_ssl=False
            )
            
            if error or not response:
                return None
            
            # Check if dangerous payload is reflected AND executable
            if self._detect_xss_reflection(payload, response):
                if self._verify_xss_execution(response, payload):
                    # Confirmed XSS - payload reflects and execution indicators present
                    finding = {
                        'type': 'XSS',
                        'status': 'XSS',
                        'url': self.target_url,
                        'test_url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'payload_type': payload_name,
                        'severity': 'High',
                        'status_code': status,
                        'proof': f"Dangerous payload reflected with execution indicators",
                        'timestamp': time.time(),
                    }
                    
                    logger.info(f"✅ [XSS] Found XSS vulnerability: {param}")
                    logger.info(f"    URL: {test_url}")
                    return finding
                else:
                    # Payload reflects but no execution indicators
                    # Now test with marker to confirm reflection capability
                    marker_payload = '"><s>superman</s>'
                    marker_url = inject_payload(self.target_url, param, marker_payload, method='query')
                    marker_response, marker_status, marker_error = make_http_request(
                        marker_url,
                        timeout=self.timeout,
                        verify_ssl=False
                    )
                    
                    if marker_response and 'superman' in marker_response:
                        # Marker reflects - this is a reflection vulnerability, not XSS
                        finding = {
                            'type': 'REFLECTION',
                            'status': 'REFLECTION',
                            'url': self.target_url,
                            'test_url': marker_url,
                            'parameter': param,
                            'payload': marker_payload,
                            'payload_type': 'marker',
                            'severity': 'Medium',
                            'status_code': marker_status,
                            'proof': f"Marker reflected (XSS payload blocked)",
                            'timestamp': time.time(),
                        }
                        
                        logger.info(f"⚠️  [REFLECTION] Found reflection vulnerability: {param}")
                        logger.info(f"    URL: {marker_url}")
                        return finding
            else:
                # Payload not reflected at all, try marker to detect reflection capability
                marker_payload = '"><s>superman</s>'
                marker_url = inject_payload(self.target_url, param, marker_payload, method='query')
                marker_response, marker_status, marker_error = make_http_request(
                    marker_url,
                    timeout=self.timeout,
                    verify_ssl=False
                )
                
                if marker_response and 'superman' in marker_response:
                    # Marker reflects even though payload didn't
                    finding = {
                        'type': 'REFLECTION',
                        'status': 'REFLECTION',
                        'url': self.target_url,
                        'test_url': marker_url,
                        'parameter': param,
                        'payload': marker_payload,
                        'payload_type': 'marker',
                        'severity': 'Medium',
                        'status_code': marker_status,
                        'proof': f"Reflection possible (marker reflects)",
                        'timestamp': time.time(),
                    }
                    
                    logger.info(f"⚠️  [REFLECTION] Found reflection vulnerability: {param}")
                    logger.info(f"    URL: {marker_url}")
                    return finding
        
        except Exception as e:
            logger.debug(f"Error testing XSS on {param}: {e}")
        
        return None
    
    def _detect_xss_reflection(self, payload: str, response: str) -> bool:
        """Detect if payload is reflected in response (including encoded variants)"""
        import html
        from urllib.parse import quote, unquote
        
        # CRITICAL: Only check for ACTUAL payload reflection, not random matches
        # The payload must be recognizable in the response, not just substrings
        
        # Check direct reflection (unencoded)
        if payload in response:
            return True
        
        # Check HTML entities (single encoding)
        html_escaped = html.escape(payload)
        if html_escaped in response:
            return True
        
        # Check URL encoding (single level)
        url_encoded = quote(payload, safe='')
        if url_encoded in response:
            return True
        
        # Check double URL encoding
        double_url = quote(quote(payload, safe=''), safe='')
        if double_url in response:
            return True
        
        # Check triple URL encoding
        triple_url = quote(quote(quote(payload, safe=''), safe=''), safe='')
        if triple_url in response:
            return True
        
        # Check HTML + URL encoding combinations
        html_then_url = quote(html.escape(payload), safe='')
        if html_then_url in response:
            return True
        
        # Check mixed encoding: URL then HTML
        url_then_html = html.escape(quote(payload, safe=''))
        if url_then_html in response:
            return True
        
        return False
    
    def _detect_reflection_context(self, param: str, marker: str, response: str) -> str:
        """
        Detect the context where the marker is reflected in the response.
        Returns the context type: html_attribute_double_quote, javascript_single_quote, etc.
        """
        import re
        
        # Look for the marker in various contexts
        marker_escaped_double = marker.replace('"', '\\"')
        marker_escaped_single = marker.replace("'", "\\'")
        
        # Pattern 1: Inside HTML attribute with double quotes
        # e.g., <input name="value_here">
        if re.search(rf'<[^>]*\s\w+="[^"]*{re.escape(marker)}[^"]*"', response):
            return "html_attribute_double_quote"
        
        # Pattern 2: Inside HTML attribute with single quotes
        # e.g., <input name='value_here'>
        if re.search(rf"<[^>]*\s\w+='[^']*{re.escape(marker)}[^']*'", response):
            return "html_attribute_single_quote"
        
        # Pattern 3: Inside JavaScript with single quotes
        # e.g., var x = 'path/superman/...'
        if re.search(rf"[=:\s]\s*'[^']*{re.escape(marker)}[^']*'", response):
            return "javascript_single_quote"
        
        # Pattern 4: Inside JavaScript with double quotes
        # e.g., var x = "path/superman/..."
        if re.search(rf'[=:\s]\s*"[^"]*{re.escape(marker)}[^"]*"', response):
            return "javascript_double_quote"
        
        # Pattern 5: Unquoted JavaScript (JSON object value, URL parameter value, etc)
        # e.g., {path: /documents/2026/2/12/...?cache-buster=batmann1&path=superman}
        if re.search(rf':\s*[^"\'{{\[,]*{re.escape(marker)}[^"\'{{\]},]*[,\]}}]', response):
            return "javascript_unquoted"
        
        # Default: just plain HTML
        return "html_text"
    
    def _is_marker_actually_reflected(self, marker: str, response: str, marker_type: str = 'generic') -> bool:
        """
        Marker reflection check - MUST be raw (unencoded) in HTML source to be exploitable.
        Only rejects when we're sure it's in a false-positive context.
        """
        if marker not in response:
            # Marker not reflected - not exploitable
            logger.debug(f"Marker not found in response")
            return False
        
        # Marker IS reflected in raw form
        idx = response.find(marker)
        logger.debug(f"Raw marker found at position {idx}")
        
        # Check 1: Is marker escaped with backslash? (e.g., \\")
        if idx > 0 and response[idx - 1:idx] == '\\':
            logger.debug(f"Marker is escaped (backslash before it) - rejecting")
            return False
        
        # For raw marker reflection, accept it
        # The marker being in raw form in the response is inherently exploitable for XSS
        logger.debug(f"✓ Raw marker reflected and not escaped - EXPLOITABLE")
        return True
    
    def _verify_xss_execution(self, response: str, payload: str) -> bool:
        """Verify that the reflected payload can actually execute code"""
        
        # CRITICAL: Check if payload is reflected AND contains executable code
        # Don't just check if response has dangerous patterns - verify the PAYLOAD itself is executable
        
        # First, ensure payload was reflected
        if payload not in response:
            # Check if it was encoded
            import html
            from urllib.parse import quote
            
            encoded_variants = [
                html.escape(payload),
                quote(payload, safe=''),
                quote(quote(payload, safe=''), safe=''),
            ]
            
            if not any(v in response for v in encoded_variants):
                return False
        
        # Second, check if the payload ITSELF is executable (contains event handlers, script tags, etc)
        payload_lower = payload.lower()
        
        executable_patterns = [
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'onchange=',
            'onmouseenter=',
            'ontouchstart=',
            '<script',
            'javascript:',
            'eval(',
            'alert(',
            'confirm(',
            'prompt(',
        ]
        
        # Payload must contain at least one executable pattern
        has_executable = any(pattern in payload_lower for pattern in executable_patterns)
        
        if not has_executable:
            # Payload doesn't contain any code execution mechanism
            return False
        
        # Now verify the executable pattern was reflected (not filtered)
        response_lower = response.lower()
        
        for pattern in executable_patterns:
            if pattern in payload_lower and pattern in response_lower:
                # Check if it appears in context of our payload
                # Look for the pattern within reasonable proximity to payload markers
                return True
        
        return False
    
    def _generate_encoding_variants(self, payload: str) -> List[str]:
        """
        Generate multi-encoding variants of a payload
        to detect XSS that manifests after multiple decode cycles
        """
        import html
        from urllib.parse import quote
        
        variants = []
        
        # Original payload
        current = payload
        
        # Generate up to 5 encoding levels
        for level in range(1, 6):
            # HTML encoding
            html_encoded = html.escape(current)
            if html_encoded != current and html_encoded not in variants:
                variants.append(html_encoded)
                current = html_encoded
            
            # URL encoding
            url_encoded = quote(current, safe='')
            if url_encoded != current and url_encoded not in variants:
                variants.append(url_encoded)
                current = url_encoded
            
            # Double URL encoding
            double_url = quote(quote(current, safe=''), safe='')
            if double_url != current and double_url not in variants:
                variants.append(double_url)
                current = double_url
        
        # Mix encoding types - HTML then URL
        current = payload
        for _ in range(3):
            current = html.escape(current)
            url_then_html = quote(current, safe='')
            if url_then_html not in variants:
                variants.append(url_then_html)
                current = url_then_html
        
        return variants[:10]  # Limit to top 10 variants for performance
    
    def _test_multi_param_xss(self, parameters: List[str], payload_name: str, payload: str) -> Optional[Dict]:
        """
        Test XSS by injecting payloads into multiple parameters simultaneously
        This detects cases where XSS only happens when multiple params are malicious
        """
        if len(parameters) < 2:
            return None
        
        test_key = f"multi_param:{payload_name}:{','.join(parameters[:3])}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            # Parse the URL to get current parameters
            parsed = urlparse(self.target_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Create a unique marker for multi-param testing
            marker = "superman"
            marker_payload = f'"><{marker}>test</{marker}>'
            
            # Test combinations of parameter injection
            combinations_to_test = [
                # Inject payload in each param individually
                {param: payload for param in parameters[:5]},
                # Inject payload in first param + marker in second
                {parameters[0]: payload, parameters[1] if len(parameters) > 1 else parameters[0]: marker_payload},
                # Inject marker in first + payload in second
                {parameters[0]: marker_payload, parameters[1] if len(parameters) > 1 else parameters[0]: payload},
            ]
            
            for combo_params in combinations_to_test:
                try:
                    # Build test URL with all parameters injected
                    test_params = params.copy()
                    test_params.update({k: [v] for k, v in combo_params.items()})
                    
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, 
                        parsed.netloc, 
                        parsed.path, 
                        parsed.params, 
                        new_query, 
                        parsed.fragment
                    ))
                    
                    # Make request
                    response, status, error = make_http_request(
                        test_url,
                        timeout=self.timeout,
                        verify_ssl=False
                    )
                    
                    if error or not response:
                        continue
                    
                    # Check if any of the injected payloads are reflected
                    for param_name, param_value in combo_params.items():
                        if self._detect_xss_reflection(param_value, response):
                            if self._verify_xss_execution(response, param_value):
                                finding = {
                                    'type': 'XSS (Multi-Parameter)',
                                    'url': self.target_url,
                                    'parameters': list(combo_params.keys()),
                                    'payload': str(combo_params),
                                    'payload_type': f"{payload_name}_multi_param",
                                    'severity': 'High',
                                    'status_code': status,
                                    'proof': f"XSS detected when injecting into multiple params: {list(combo_params.keys())}",
                                    'timestamp': time.time(),
                                }
                                
                                logger.info(f"✅ [XSS] Found multi-parameter vulnerability: {list(combo_params.keys())}")
                                return finding
                
                except Exception as e:
                    logger.debug(f"Error in multi-param test: {e}")
        
        except Exception as e:
            logger.debug(f"Error testing multi-parameter XSS: {e}")
        
        return None
    
    def _scan_sqli(self, parameters: List[str]):
        """Advanced SQL Injection scanning"""
        logger.info("🔍 [SQLi] Starting SQL Injection scan...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for param in parameters:
                # Test each method
                future_error = executor.submit(self._test_sqli_error_based, param)
                future_bool = executor.submit(self._test_sqli_boolean_based, param)
                future_time = executor.submit(self._test_sqli_time_based, param)
                
                futures.extend([future_error, future_bool, future_time])
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        if self.live_output:
                            self._print_finding(result)
                except Exception as e:
                    logger.debug(f"Error in SQLi test: {e}")
        
        logger.info(f"✅ SQLi scan complete")
    
    def _test_sqli_error_based(self, param: str) -> Optional[Dict]:
        """Test for error-based SQL injection"""
        
        test_key = f"{param}:sqli_error"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            for payload in SQLI_PAYLOADS.get('error_based', [])[:10]:  # Limit payloads for speed
                test_url = inject_payload(self.target_url, param, payload, method='query')
                
                response, status, _ = make_http_request(
                    test_url,
                    timeout=self.timeout,
                    verify_ssl=False
                )
                
                if response and self._detect_sqli_error(response):
                    finding = {
                        'type': 'SQL Injection (Error-Based)',
                        'url': self.target_url,
                        'parameter': param,
                        'payload': payload,
                        'method': 'error-based',
                        'severity': 'Critical',
                        'proof': 'SQL error message detected in response',
                        'timestamp': time.time(),
                    }
                    
                    logger.info(f"✅ [SQLi] Found error-based vulnerability: {param}")
                    return finding
        
        except Exception as e:
            logger.debug(f"Error testing SQLi error-based on {param}: {e}")
        
        return None
    
    def _test_sqli_boolean_based(self, param: str) -> Optional[Dict]:
        """Test for boolean-based SQL injection"""
        
        test_key = f"{param}:sqli_bool"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            # Get baseline response
            baseline_resp, _, _ = make_http_request(self.target_url, timeout=self.timeout, verify_ssl=False)
            
            if not baseline_resp:
                return None
            
            baseline_len = len(baseline_resp)
            
            # Test true condition
            true_payload = "' AND '1'='1"
            true_url = inject_payload(self.target_url, param, true_payload, method='query')
            true_resp, _, _ = make_http_request(true_url, timeout=self.timeout, verify_ssl=False)
            
            if not true_resp:
                return None
            
            # Test false condition
            false_payload = "' AND '1'='2"
            false_url = inject_payload(self.target_url, param, false_payload, method='query')
            false_resp, status, _ = make_http_request(false_url, timeout=self.timeout, verify_ssl=False)
            
            if not false_resp:
                return None
            
            true_len = len(true_resp)
            false_len = len(false_resp)
            
            # Analyze response differences
            if abs(true_len - false_len) > 50:
                finding = {
                    'type': 'SQL Injection (Boolean-Based)',
                    'url': self.target_url,
                    'parameter': param,
                    'payload': true_payload,
                    'method': 'boolean-based',
                    'severity': 'High',
                    'proof': f'Response diff: baseline={baseline_len}, true={true_len}, false={false_len}',
                    'timestamp': time.time(),
                }
                
                logger.info(f"✅ [SQLi] Found boolean-based vulnerability: {param}")
                return finding
        
        except Exception as e:
            logger.debug(f"Error testing SQLi boolean on {param}: {e}")
        
        return None
    
    def _test_sqli_time_based(self, param: str) -> Optional[Dict]:
        """Test for time-based SQL injection"""
        
        test_key = f"{param}:sqli_time"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            payload = "' AND SLEEP(5) -- -"
            test_url = inject_payload(self.target_url, param, payload, method='query')
            
            start_time = time.time()
            response, status, _ = make_http_request(test_url, timeout=10, verify_ssl=False)
            elapsed = time.time() - start_time
            
            # If response took at least 4 seconds, likely time-based SQLi
            if elapsed >= 4:
                finding = {
                    'type': 'SQL Injection (Time-Based)',
                    'url': self.target_url,
                    'parameter': param,
                    'payload': payload,
                    'method': 'time-based',
                    'severity': 'High',
                    'proof': f'Response delayed by {elapsed:.2f}s (expected ~5s)',
                    'timestamp': time.time(),
                }
                
                logger.info(f"✅ [SQLi] Found time-based vulnerability: {param}")
                return finding
        
        except Exception as e:
            logger.debug(f"Error testing SQLi time-based on {param}: {e}")
        
        return None
    
    def _detect_sqli_error(self, response: str) -> bool:
        """Detect SQL error messages"""
        
        error_indicators = [
            'sql syntax',
            'mysql_fetch',
            'warning: mysql',
            'fatal error',
            'unclosed quotation',
            'quoted string not properly terminated',
            'syntax error',
            'database error',
            'postgresql error',
            'ora-',  # Oracle
            'error in your sql',
            'mysql error',
            'pdo exception',
        ]
        
        response_lower = response.lower()
        
        for indicator in error_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    def _scan_ssrf(self, parameters: List[str]):
        """SSRF scanning"""
        logger.info("🔍 [SSRF] Starting SSRF scan...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for param in parameters:
                for payload in SSRF_PAYLOADS[:5]:  # Limit payloads
                    future = executor.submit(self._test_ssrf, param, payload)
                    futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        if self.live_output:
                            self._print_finding(result)
                except Exception as e:
                    logger.debug(f"Error in SSRF test: {e}")
        
        logger.info(f"✅ SSRF scan complete")
    
    def _test_ssrf(self, param: str, payload: str) -> Optional[Dict]:
        """Test for SSRF"""
        
        test_key = f"{param}:{payload}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            test_url = inject_payload(self.target_url, param, payload, method='query')
            response, status, _ = make_http_request(test_url, timeout=self.timeout, verify_ssl=False)
            
            if response and self._detect_ssrf_indicators(response):
                finding = {
                    'type': 'SSRF',
                    'url': self.target_url,
                    'parameter': param,
                    'payload': payload,
                    'severity': 'High',
                    'proof': 'Internal service response detected',
                    'timestamp': time.time(),
                }
                
                logger.info(f"✅ [SSRF] Found vulnerability: {param}")
                return finding
        
        except Exception as e:
            logger.debug(f"Error testing SSRF on {param}: {e}")
        
        return None
    
    def _scan_xxe(self, parameters: List[str]):
        """Advanced XXE scanning with blind detection"""
        logger.info("🔍 [XXE] Starting XXE scan...")
        
        # Use dedicated XXE scanner with blind detection
        scanner = XXEScanner(blind_detection=self.deep or self.aggressive)
        
        # Build URLs with parameters to test
        test_urls = []
        for param in parameters[:10]:  # Limit to prevent excessive testing
            test_urls.append(self.target_url)
        
        # Run XXE scanner
        try:
            xxe_findings = scanner.scan_urls(test_urls)
            if xxe_findings:
                self.findings.extend(xxe_findings)
                logger.info(f"✅ [XXE] Found {len(xxe_findings)} XXE vulnerabilities")
                for finding in xxe_findings:
                    if self.live_output:
                        self._print_finding(finding)
        except Exception as e:
            logger.debug(f"Error in XXE scanning: {e}")
    
    def _scan_path_based_xss(self):
        """Scan for XSS in URL path segments"""
        self.log_info("🔍 [PATH-XSS] Starting path-based XSS scanning...")
        
        parsed = urlparse(self.target_url)
        path_segments = [s for s in parsed.path.split('/') if s]
        
        if not path_segments:
            logger.debug("No path segments to test")
            return
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for i, segment in enumerate(path_segments):
                for payload_name, payload in PATH_XSS_PAYLOADS.items():
                    future = executor.submit(self._test_path_xss, i, segment, payload_name, payload)
                    futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        if self.live_output:
                            self._print_finding(result)
                except Exception as e:
                    logger.debug(f"Error in path XSS test: {e}")
        
        logger.info("✅ Path-based XSS scan complete")
    
    def _test_path_xss(self, segment_index: int, segment: str, payload_name: str, payload: str) -> Optional[Dict]:
        """Test path segment for XSS"""
        
        test_key = f"path:{segment_index}:{payload_name}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            # Replace path segment with payload
            parsed = urlparse(self.target_url)
            path_segments = [s for s in parsed.path.split('/') if s]
            
            if segment_index >= len(path_segments):
                return None
            
            path_segments[segment_index] = payload
            new_path = '/' + '/'.join(path_segments)
            
            # Reconstruct URL
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            response, status, _ = make_http_request(
                test_url,
                timeout=self.timeout,
                verify_ssl=False
            )
            
            if not response:
                return None
            
            # Check for reflection
            if self._detect_xss_reflection(payload, response):
                if self._verify_xss_execution(response, payload):
                    finding = {
                        'type': 'XSS (Path-Based)',
                        'url': test_url,
                        'parameter': f'path_segment_{segment_index}',
                        'payload': payload,
                        'payload_type': payload_name,
                        'severity': 'High',
                        'proof': 'Payload reflected in path response',
                        'timestamp': time.time(),
                    }
                    
                    logger.info(f"✅ [PATH-XSS] Found vulnerability in path segment {segment_index}")
                    return finding
        
        except Exception as e:
            logger.debug(f"Error testing path XSS on segment {segment_index}: {e}")
        
        return None
    
    def _scan_custom_parameters(self):
        """Scan by injecting XSS payloads into custom parameters"""
        self.log_info("🔍 [CUSTOM-PARAM] Starting custom parameter injection scanning...")

        # Default xss-only behavior: marker-based probing only (safe, low-noise).
        # Use dangerous payload set only when user explicitly requests xss_verbose mode.
        if self.silent:
            payloads = CUSTOM_PARAM_PAYLOADS
        else:
            payloads = {
                'tag_break': '"><s>superman',
                'attribute_quote': '" superman',
            }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for param_name in CUSTOM_PARAM_NAMES:
                for payload_name, payload in payloads.items():
                    future = executor.submit(self._test_custom_parameter, param_name, payload_name, payload)
                    futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        if self.live_output:
                            self._print_finding(result)
                except Exception as e:
                    logger.debug(f"Error in custom param test: {e}")
        
        logger.info("✅ Custom parameter injection scan complete")
    
    def _test_custom_parameter(self, param_name: str, payload_name: str, payload: str) -> Optional[Dict]:
        """Test injecting payload as a new custom parameter"""
        
        test_key = f"custom_param:{param_name}:{payload_name}"
        test_hash = calculate_hash(test_key)
        
        if test_hash in self.tested:
            return None
        self.tested.add(test_hash)
        
        try:
            # Add new parameter to URL
            test_url = inject_payload(self.target_url, param_name, payload, method='query')
            
            response, status, _ = make_http_request(
                test_url,
                timeout=self.timeout,
                verify_ssl=False
            )
            
            if not response:
                return None
            
            # In default mode, treat this as injectability detection (marker breakout),
            # not full XSS execution detection.
            if not self.xss_verbose:
                if self._is_marker_actually_reflected(payload, response, payload_name):
                    finding = {
                        'type': 'INJECTABLE',
                        'status': '[INJECTABLE]',
                        'url': self.target_url,
                        'test_url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'payload_type': payload_name,
                        'severity': 'Medium',
                        'proof': f'Marker reflected in exploitable HTML context for custom parameter: {param_name}',
                        'timestamp': time.time(),
                    }

                    logger.info(f"✅ [CUSTOM-PARAM][INJECTABLE] Found injectable custom parameter: {param_name} ({payload_name})")
                    return finding
            else:
                # Verbose mode keeps dangerous payload execution checks.
                if self._detect_xss_reflection(payload, response):
                    if self._verify_xss_execution(response, payload):
                        finding = {
                            'type': 'XSS (Custom Parameter)',
                            'url': self.target_url,
                            'test_url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'payload_type': payload_name,
                            'severity': 'High',
                            'proof': f'Payload reflected when injected as new parameter: {param_name}',
                            'timestamp': time.time(),
                        }

                        logger.info(f"✅ [CUSTOM-PARAM] Found vulnerability in parameter: {param_name}")
                        return finding
        
        except Exception as e:
            logger.debug(f"Error testing custom parameter {param_name}: {e}")
        
        return None
    
    def _scan_sqli_with_sqlmap(self):
        """Use sqlmap for comprehensive SQL injection testing"""
        self.log_info("🔍 [SQLMAP] Starting sqlmap-based SQL injection scan...")
        
        if not check_tool_exists('sqlmap', 'sqlmap --version'):
            logger.warning("⚠️  sqlmap not installed. Skipping sqlmap scanning.")
            logger.info("ℹ️  Install with: pip install sqlmap")
            return
        
        try:
            # Basic sqlmap command
            cmd = [
                'sqlmap',
                '-u', self.target_url,
                '--batch',  # Batch mode (don't ask for input)
                '--json-file', '/tmp/sqlmap_output.json',
                '--risk', '2' if self.aggressive else '1',
                '--level', '3' if self.deep else '1',
                '-v', '0',  # Minimal verbosity
            ]
            
            if self.timeout is not None:
                cmd.extend(['--timeout', str(self.timeout)])
            
            if self.bypass_waf:
                cmd.extend(['--tamper=space2comment,between'])
            
            logger.debug(f"Running: {' '.join(cmd)}")
            result = run_command(' '.join(cmd))
            
            # Try to parse JSON output
            try:
                import json
                import os
                
                json_file = '/tmp/sqlmap_output.json'
                if os.path.exists(json_file):
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                    
                    if data and len(data) > 0:
                        for item in data:
                            if item.get('type') == 'INJECTABLE' or 'vulnerable' in str(item).lower():
                                finding = {
                                    'type': 'SQL Injection (sqlmap)',
                                    'url': self.target_url,
                                    'parameter': item.get('parameter', 'N/A'),
                                    'payload': item.get('payload', 'N/A'),
                                    'severity': 'Critical',
                                    'proof': str(item),
                                    'source': 'sqlmap',
                                    'timestamp': time.time(),
                                }
                                
                                self.findings.append(finding)
                                if self.live_output:
                                    self._print_finding(finding)
                                
                                logger.info(f"✅ [SQLMAP] Found SQL injection in {item.get('parameter')}")
            
            except (json.JSONDecodeError, FileNotFoundError):
                # Parse text output if JSON parsing fails
                if result and ('vulnerable' in result.lower() or 'injectable' in result.lower()):
                    logger.info("✅ [SQLMAP] Potential SQL injection found")
        
        except Exception as e:
            logger.debug(f"sqlmap scanning error: {e}")
        
        logger.info("✅ sqlmap scan complete")
    def _discover_parameters_with_tools(self):
        """Use various tools to discover parameters and URLs"""
        logger.info("🔍 [PARAM-DISCOVERY] Starting parameter discovery...")
        
        discovered_params = set()
        discovered_urls = []
        
        # Try Playwright spider first for live parameter discovery from navigation
        if not self.silent:
            logger.info("🌐 Attempting Playwright headless browser crawling...")
        try:
            spider_result = run_playwright_spider(
                self.target_url, 
                timeout=self.timeout,
                max_pages=20,
                verbose=self.verbose,
                silent=self.silent
            )
            
            if spider_result and spider_result.get("parameters"):
                discovered_params.update(spider_result["parameters"])
                if spider_result.get("urls"):
                    discovered_urls.extend(spider_result["urls"])
                logger.info(f"✅ Playwright discovered {len(spider_result['parameters'])} parameters")
                if self.verbose:
                    logger.info(f"   Parameters: {', '.join(list(spider_result['parameters'])[:15])}")
        
        except Exception as e:
            logger.debug(f"Playwright spider error (this is optional): {e}")
        
        # Try gau piped to katana - discovers URLs AND parameters
        gau_exists = check_tool_exists('gau', 'gau --version')
        katana_exists = check_tool_exists('katana', 'katana -h')
        
        if gau_exists and katana_exists:
            self.log_info("🔍 [GAU+KATANA] Running URL enumeration with gau piped to katana (deep crawl)...")
            try:
                domain = get_domain_from_url(self.target_url)
                cmd = f"echo '{domain}' | gau | katana -depth 3 -jc -c 50 2>&1"
                success, result, error = run_command(cmd)
                
                if success and result:
                    katana_urls = []
                    katana_params_before = len(discovered_params)
                    
                    for line in result.split('\n'):
                        line = line.strip()
                        # Parse katana's [INF] output format: [INF] Started standard crawling for => <URL>
                        if '[INF] Started standard crawling for =>' in line:
                            url = line.split('[INF] Started standard crawling for => ')[-1].strip()
                            if url and url.startswith('http'):
                                katana_urls.append(url)
                                discovered_urls.append(url)
                                try:
                                    parsed = urlparse(url)
                                    params = parse_qs(parsed.query, keep_blank_values=True)
                                    discovered_params.update(params.keys())
                                except:
                                    pass
                        # Also check for raw URLs in case output format changes
                        elif line and line.startswith('http') and '[INF]' not in line:
                            katana_urls.append(line)
                            discovered_urls.append(line)
                            try:
                                parsed = urlparse(line)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                discovered_params.update(params.keys())
                            except:
                                pass
                    
                    katana_params_new = len(discovered_params) - katana_params_before
                    logger.info(f"   ✅ Gau→Katana found {len(katana_urls)} URLs with {katana_params_new} new parameters")
                    if self.verbose and katana_urls:
                        logger.info(f"   Sample URLs: {', '.join(katana_urls[:3])}")
                else:
                    logger.info(f"   ⚠️  Gau→Katana found no URLs")
            
            except Exception as e:
                logger.debug(f"gau→katana error: {e}")
        
        # Try waybackurls piped to katana - discovers historical URLs with parameters
        wayback_exists = check_tool_exists('waybackurls', 'waybackurls -h')
        
        if wayback_exists and katana_exists:
            self.log_info("🔍 [WAYBACKURLS+KATANA] Running URL enumeration with waybackurls piped to katana (deep crawl)...")
            try:
                domain = get_domain_from_url(self.target_url)
                cmd = f"echo '{domain}' | waybackurls | katana -depth 3 -jc -c 50 2>&1"
                success, result, error = run_command(cmd)
                
                if success and result:
                    wayback_urls = []
                    wayback_params_before = len(discovered_params)
                    
                    for line in result.split('\n'):
                        line = line.strip()
                        # Parse katana's [INF] output format
                        if '[INF] Started standard crawling for =>' in line:
                            url = line.split('[INF] Started standard crawling for => ')[-1].strip()
                            if url and url.startswith('http'):
                                wayback_urls.append(url)
                                discovered_urls.append(url)
                                try:
                                    parsed = urlparse(url)
                                    params = parse_qs(parsed.query, keep_blank_values=True)
                                    discovered_params.update(params.keys())
                                except:
                                    pass
                        # Also check for raw URLs
                        elif line and line.startswith('http') and '[INF]' not in line:
                            wayback_urls.append(line)
                            discovered_urls.append(line)
                            try:
                                parsed = urlparse(line)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                discovered_params.update(params.keys())
                            except:
                                pass
                    
                    wayback_params_new = len(discovered_params) - wayback_params_before
                    logger.info(f"   ✅ Waybackurls→Katana found {len(wayback_urls)} historical URLs with {wayback_params_new} new parameters")
                    if self.verbose and wayback_urls:
                        logger.info(f"   Sample URLs: {', '.join(wayback_urls[:3])}")
                else:
                    logger.info(f"   ⚠️  Waybackurls→Katana found no URLs")
            
            except Exception as e:
                logger.debug(f"waybackurls→katana error: {e}")
        
        # Try katana directly on target URL as fallback
        if katana_exists:
            self.log_info("🔍 [KATANA-DIRECT] Running URL crawling with katana directly on target (deep crawl)...")
            try:
                cmd = f"katana -u {self.target_url} -depth 3 -jc -c 50 2>&1"
                success, result, error = run_command(cmd)
                
                if success and result:
                    katana_direct_urls = []
                    katana_direct_params_before = len(discovered_params)
                    
                    for line in result.split('\n'):
                        line = line.strip()
                        # Parse katana's [INF] output format
                        if '[INF] Started standard crawling for =>' in line:
                            url = line.split('[INF] Started standard crawling for => ')[-1].strip()
                            if url and url.startswith('http'):
                                katana_direct_urls.append(url)
                                discovered_urls.append(url)
                                try:
                                    parsed = urlparse(url)
                                    params = parse_qs(parsed.query, keep_blank_values=True)
                                    discovered_params.update(params.keys())
                                except:
                                    pass
                        # Also check for raw URLs
                        elif line and line.startswith('http') and '[INF]' not in line:
                            katana_direct_urls.append(line)
                            discovered_urls.append(line)
                            try:
                                parsed = urlparse(line)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                discovered_params.update(params.keys())
                            except:
                                pass
                    
                    katana_direct_params_new = len(discovered_params) - katana_direct_params_before
                    logger.info(f"   ✅ Katana-Direct found {len(katana_direct_urls)} URLs with {katana_direct_params_new} new parameters")
                    if self.verbose and katana_direct_urls:
                        logger.info(f"   Sample URLs: {', '.join(katana_direct_urls[:3])}")
                else:
                    logger.info(f"   ⚠️  Katana-Direct found no URLs")
            
            except Exception as e:
                logger.debug(f"katana-direct error: {e}")
        
        # Try paramspider piped to katana
        if check_tool_exists('paramspider', 'paramspider -h') and check_tool_exists('katana', 'katana -h'):
            self.log_info("🔍 [PARAMSPIDER+KATANA] Running parameter enumeration with paramspider (multi-threaded) piped to katana...")
            try:
                domain = get_domain_from_url(self.target_url)
                cmd = f"paramspider -d {domain} -l 100 -t 10 -s 2>/dev/null | katana -depth 2 -jc -c 50 2>&1"
                success, result, error = run_command(cmd)
                
                if success and result:
                    spider_urls = []
                    spider_params_before = len(discovered_params)
                    
                    for line in result.split('\n'):
                        line = line.strip()
                        # Parse katana's [INF] output format
                        if '[INF] Started standard crawling for =>' in line:
                            url = line.split('[INF] Started standard crawling for => ')[-1].strip()
                            if url and url.startswith('http'):
                                spider_urls.append(url)
                                discovered_urls.append(url)
                                try:
                                    parsed = urlparse(url)
                                    params = parse_qs(parsed.query, keep_blank_values=True)
                                    discovered_params.update(params.keys())
                                except:
                                    pass
                        # Also check for raw URLs
                        elif line and line.startswith('http') and '[INF]' not in line:
                            spider_urls.append(line)
                            discovered_urls.append(line)
                            try:
                                parsed = urlparse(line)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                discovered_params.update(params.keys())
                            except:
                                pass
                    
                    spider_params_new = len(discovered_params) - spider_params_before
                    logger.info(f"   ✅ Paramspider→Katana found {len(spider_urls)} URLs with {spider_params_new} new parameters")
                    if self.verbose and spider_urls:
                        logger.info(f"   Sample URLs: {', '.join(spider_urls[:3])}")
                else:
                    logger.info(f"   ⚠️  Paramspider→Katana found no URLs")
            
            except Exception as e:
                logger.debug(f"paramspider→katana error: {e}")

        # Exhaustive ParamSpider expansion across all discovered hosts.
        # ParamSpider operates at domain scope, so we run it for each unique host found.
        if check_tool_exists('paramspider', 'paramspider -h'):
            try:
                all_hosts = set()
                all_hosts.add(urlparse(self.target_url).netloc)
                for u in discovered_urls:
                    try:
                        host = urlparse(u).netloc
                        if host:
                            all_hosts.add(host)
                    except Exception:
                        pass

                if all_hosts:
                    self.log_info(f"🔍 [PARAMSPIDER-ALL] Running paramspider on {len(all_hosts)} discovered host(s)...")

                for host in sorted(all_hosts):
                    try:
                        cmd = f"paramspider -d {host} -s 2>/dev/null | head -2000"
                        success, result, error = run_command(cmd)
                        if not success or not result:
                            continue

                        before_params = len(discovered_params)
                        before_urls = len(discovered_urls)

                        for line in result.split('\n'):
                            line = line.strip()
                            if not line.startswith('http'):
                                continue

                            discovered_urls.append(line)
                            try:
                                parsed = urlparse(line)
                                params = parse_qs(parsed.query, keep_blank_values=True)
                                discovered_params.update(params.keys())
                            except Exception:
                                pass

                        new_params = len(discovered_params) - before_params
                        new_urls = len(discovered_urls) - before_urls
                        if new_urls > 0 or new_params > 0:
                            logger.info(f"   ✅ ParamSpider-All({host}) found {new_urls} URLs and {new_params} new parameters")

                    except Exception as e:
                        logger.debug(f"paramspider-all error for {host}: {e}")
            except Exception as e:
                logger.debug(f"paramspider-all setup error: {e}")
        
        if discovered_params:
            logger.info(f"✅ Discovered {len(discovered_params)} unique parameters: {', '.join(list(discovered_params)[:10])}")
        
        if discovered_urls:
            discovered_urls = list(dict.fromkeys(discovered_urls))
            logger.info(f"✅ Discovered {len(discovered_urls)} unique URLs with parameters")
            # Store URLs for later testing
            self.discovered_urls = discovered_urls
            if self.verbose:
                logger.info(f"   URLs will be tested individually for XSS injection")
        
        return list(discovered_params)
    
    def _detect_ssrf_indicators(self, response: str) -> bool:
        """Detect SSRF indicators"""
        
        indicators = [
            '127.0.0.1',
            'localhost',
            '192.168.',
            '10.0.',
            '169.254.169.254',  # AWS metadata
        ]
        
        for indicator in indicators:
            if indicator in response:
                return True
        
        return False
    
    def _scan_nuclei(self) -> None:
        """Scan using Nuclei templates for comprehensive vulnerability detection"""
        self.log_info("🔍 [NUCLEI] Starting Nuclei template-based scanning...")
        
        # Check if nuclei is available
        if not check_tool_exists('nuclei', 'nuclei -version'):
            logger.warning("⚠️  Nuclei not installed. Skipping template-based scanning.")
            logger.info("   To install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            return
        
        try:
            # Determine nuclei tags based on scan_types
            if self.scan_types and len(self.scan_types) == 1:
                # Single vulnerability type - use specific tag
                scan_type = self.scan_types[0]
                tags = scan_type if scan_type in ['xss', 'sqli', 'ssrf', 'xxe', 'lfi'] else 'cves,vulnerabilities,misconfigurations'
            else:
                # Multiple types or default - use all template categories
                tags = 'cves,vulnerabilities,misconfigurations'
            
            # Run nuclei with multiple template categories
            cmd = [
                'nuclei',
                '-u', self.target_url,
                '-tags', tags,
                '-json',  # JSON output
                '-severity', 'critical,high,medium',  # Filter by severity
            ]
            
            # Add timeout only if specified (not unlimited)
            if self.timeout is not None:
                cmd.extend(['-timeout', str(self.timeout)])
            
            if self.verbose:
                logger.info(f"Running: {' '.join(cmd)}")
            
            # Execute nuclei and capture output
            success, result_str, error = run_command(' '.join(cmd))
            
            if not success or not result_str:
                logger.info("✅ Nuclei scan completed with no vulnerabilities")
                return
            
            # Convert to string if needed
            result_str = str(result_str) if result_str else ""
            
            if 'error' in result_str.lower() and 'no results' in result_str.lower():
                logger.info("✅ Nuclei scan completed with no vulnerabilities")
                return
            
            # Parse JSON output from nuclei
            import json
            
            for line in result_str.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Convert nuclei output to our findings format
                    finding = {
                        'type': f"Nuclei: {data.get('info', {}).get('name', 'Unknown')}",
                        'parameter': self.target_url.split('?')[1] if '?' in self.target_url else 'N/A',
                        'url': self.target_url,
                        'proof': data.get('matched-at', data.get('template-id', 'Vulnerability detected')),
                        'severity': data.get('info', {}).get('severity', 'Medium').capitalize(),
                        'template_id': data.get('template-id', 'N/A'),
                        'source': 'nuclei',
                    }
                    
                    self.findings.append(finding)
                    
                    if self.live_output:
                        self._print_finding(finding)
                    
                    logger.info(f"✅ [NUCLEI] Found: {finding['type']} ({finding['severity']})")
                
                except json.JSONDecodeError:
                    continue
        
        except Exception as e:
            logger.warning(f"⚠️  Nuclei scanning error: {e}")
        
        logger.info("✅ Nuclei scan complete")
    
    def _scan_nuclei_advanced(self) -> None:
        """Advanced Nuclei scanning with custom filters and templates"""
        logger.info("🔍 [NUCLEI-ADVANCED] Starting advanced template scanning...")
        
        if not check_tool_exists('nuclei', 'nuclei -version'):
            logger.info("ℹ️  Nuclei not available, skipping advanced scanning")
            return
        
        try:
            # Determine nuclei tags based on scan_types
            if self.scan_types and len(self.scan_types) == 1:
                # Single vulnerability type - use specific tag
                scan_type = self.scan_types[0]
                tags = scan_type if scan_type in ['xss', 'sqli', 'ssrf', 'xxe', 'lfi'] else 'cves,vulnerabilities,misconfigurations'
            else:
                # Multiple types or default - use all template categories
                tags = 'cves,vulnerabilities,misconfigurations,exposures'
            
            # Advanced nuclei command with more options
            severity = 'critical,high,medium' if self.deep else 'critical,high'
            
            cmd = [
                'nuclei',
                '-u', self.target_url,
                '-tags', tags,
                '-auto-calibrate',  # Auto calibrate for accuracy
                '-json',
                '-severity', severity,
            ]
            
            # Add timeout only if specified (not unlimited)
            if self.timeout is not None:
                cmd.extend(['-timeout', str(self.timeout)])
            
            if self.bypass_waf:
                cmd.extend(['-retries', '3'])  # Retry for WAF bypass
            
            if self.deep:
                # Include more template categories in deep mode
                cmd.extend(['-include-templates', 'cves,vulnerabilities,misconfigurations,exposures'])
            
            success, result, error = run_command(' '.join(cmd))
            
            if not success or not result or result.strip() == '':
                return
            
            # Parse results
            import json
            
            for line in result.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Skip if already found by other methods
                    template_id = data.get('template-id', '')
                    if template_id in [f.get('template_id') for f in self.findings]:
                        continue
                    
                    finding = {
                        'type': f"Nuclei: {data.get('info', {}).get('name', 'Unknown')}",
                        'parameter': 'N/A',
                        'url': data.get('matched-at', self.target_url),
                        'proof': data.get('curl-command', data.get('request', '')),
                        'severity': data.get('info', {}).get('severity', 'Medium').capitalize(),
                        'template_id': template_id,
                        'source': 'nuclei-advanced',
                        'matcher_name': data.get('matcher-name', 'N/A'),
                    }
                    
                    self.findings.append(finding)
                    
                    if self.live_output:
                        self._print_finding(finding)
                    
                    logger.info(f"✅ [NUCLEI] {finding['type']} ({finding['severity']})")
                
                except json.JSONDecodeError:
                    continue
        
        except Exception as e:
            logger.warning(f"⚠️  Advanced Nuclei error: {e}")
    
    def _print_finding(self, finding: Dict):
        """Print a single finding with formatted output"""
        
        severity_colors = {
            'Critical': '\033[91m',
            'High': '\033[93m',
            'Medium': '\033[94m',
            'Low': '\033[92m',
        }
        reset = '\033[0m'
        
        color = severity_colors.get(finding.get('severity', 'Info'), '')
        finding_type = finding.get('type', 'Unknown')
        status = finding.get('status', finding_type)
        
        # Format: "✅ [XSS] found at https://target.com?param=PAYLOAD"
        if status == 'XSS':
            print(f"{color}✅ [XSS]{reset} found at {finding.get('test_url', finding.get('url', 'N/A'))}")
        elif status == 'REFLECTION':
            print(f"{color}⚠️  [REFLECTION]{reset} found at {finding.get('test_url', finding.get('url', 'N/A'))}")
        else:
            print(f"{color}[{status.upper()}]{reset} {finding.get('type', 'Unknown')}")
            print(f"  URL: {finding.get('test_url', finding.get('url', 'N/A'))}")
        
        print(f"  Parameter: {finding.get('parameter', 'N/A')}")
        print(f"  Payload Type: {finding.get('payload_type', 'N/A')}")
        print(f"  Severity: {finding.get('severity', 'N/A')}")
        if finding.get('proof'):
            print(f"  Proof: {finding.get('proof')}")
        print()
