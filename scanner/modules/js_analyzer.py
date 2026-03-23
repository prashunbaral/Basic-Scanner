"""
JavaScript analysis module for endpoint and sink discovery
"""
import re
import concurrent.futures
from typing import List, Set, Dict, Optional, Tuple
from scanner.logger import logger
from scanner.utils import make_http_request, get_domain_from_url
from scanner.config import MAX_WORKERS, JS_ENDPOINT_PATTERNS, XSS_SINK_PATTERNS, TIMEOUT
import requests

class JSAnalyzer:
    """Analyzes JavaScript files for endpoints, parameters, and sinks"""
    
    def __init__(self):
        self.discovered_endpoints = set()
        self.discovered_params = set()
        self.xss_sinks = {}  # {url: [sink_list]}
        logger.info("JSAnalyzer initialized")
    
    def analyze_js_files(self, js_urls: List[str]) -> Tuple[Set[str], Set[str], Dict]:
        """
        Analyze JavaScript files for endpoints and sinks
        
        Args:
            js_urls: List of JavaScript file URLs
        
        Returns:
            (discovered_endpoints, discovered_params, xss_sinks)
        """
        logger.info(f"Analyzing {len(js_urls)} JavaScript files...")
        
        # Process in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self._analyze_single_js, url): url for url in js_urls}
            
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    endpoints, params, sinks = future.result()
                    self.discovered_endpoints.update(endpoints)
                    self.discovered_params.update(params)
                    if sinks:
                        self.xss_sinks[url] = sinks
                except Exception as e:
                    logger.debug(f"Error analyzing {url}: {e}")
        
        logger.info(f"Discovered {len(self.discovered_endpoints)} endpoints from JS")
        logger.info(f"Discovered {len(self.discovered_params)} parameters from JS")
        logger.info(f"Found {len(self.xss_sinks)} files with XSS sinks")
        
        return self.discovered_endpoints, self.discovered_params, self.xss_sinks
    
    def _analyze_single_js(self, url: str) -> Tuple[Set[str], Set[str], List[str]]:
        """Analyze a single JavaScript file"""
        try:
            content, status, error = make_http_request(url, timeout=TIMEOUT)
            
            if error or not content:
                logger.debug(f"Error fetching {url}: {error}")
                return set(), set(), []
            
            # Extract endpoints
            endpoints = self._extract_endpoints(content)
            
            # Extract parameters
            params = self._extract_parameters(content)
            
            # Find XSS sinks
            sinks = self._find_xss_sinks(content)
            
            return endpoints, params, sinks
            
        except Exception as e:
            logger.debug(f"Error analyzing JS {url}: {e}")
            return set(), set(), []
    
    def _extract_endpoints(self, js_content: str) -> Set[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = set()
        
        for pattern in JS_ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    # Clean up the endpoint
                    endpoint = match.strip('"\'')
                    # Filter out obviously invalid endpoints
                    if endpoint and len(endpoint) > 2 and not endpoint.startswith('http'):
                        endpoints.add(endpoint)
            except:
                pass
        
        return endpoints
    
    def _extract_parameters(self, js_content: str) -> Set[str]:
        """Extract parameter names from JavaScript"""
        params = set()
        
        # Common parameter extraction patterns
        patterns = [
            r'(?:param|parameter|query|get|post|data)\s*[:=]\s*["\']?(\w+)["\']?',
            r'\?(\w+)=',
            r'&(\w+)=',
            r'["\'](\w+)["\']:\s*["\']?\$',
            r'params\.(\w+)',
            r'req\.query\.(\w+)',
            r'req\.body\.(\w+)',
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    if match and len(match) > 1:
                        params.add(match.lower())
            except:
                pass
        
        return params
    
    def _find_xss_sinks(self, js_content: str) -> List[str]:
        """Find potential XSS sinks in JavaScript"""
        sinks = []
        
        for pattern in XSS_SINK_PATTERNS:
            try:
                if re.search(pattern, js_content, re.IGNORECASE):
                    sinks.append(pattern)
            except:
                pass
        
        return sinks
    
    def get_stored_xss_sources(self, js_content: str) -> List[Dict]:
        """
        Identify potential stored XSS sources
        Returns list of {source, sink} pairs
        """
        sources = []
        
        # Look for DOM sources
        source_patterns = [
            r'document\.location',
            r'window\.location',
            r'document\.URL',
            r'document\.referrer',
            r'\.hash',
            r'\.search',
            r'\.pathname',
        ]
        
        for source_pattern in source_patterns:
            if re.search(source_pattern, js_content, re.IGNORECASE):
                # Check if it flows to a sink
                for sink_pattern in XSS_SINK_PATTERNS:
                    if re.search(sink_pattern, js_content, re.IGNORECASE):
                        sources.append({
                            'source': source_pattern,
                            'sink': sink_pattern,
                            'type': 'potential_stored_xss'
                        })
        
        return sources
    
    def analyze_url_pattern_js(self, base_url: str) -> Dict[str, any]:
        """Analyze JavaScript patterns for a specific URL"""
        try:
            content, status, error = make_http_request(base_url, timeout=TIMEOUT)
            
            if error or not content:
                return {'error': error, 'status': status}
            
            analysis = {
                'url': base_url,
                'endpoints': list(self._extract_endpoints(content)),
                'parameters': list(self._extract_parameters(content)),
                'xss_sinks': self._find_xss_sinks(content),
                'stored_xss_sources': self.get_stored_xss_sources(content),
            }
            
            return analysis
        except Exception as e:
            logger.error(f"Error analyzing JS patterns in {base_url}: {e}")
            return {'error': str(e)}
    
    def get_summary(self) -> Dict:
        """Get analysis summary"""
        return {
            'discovered_endpoints': len(self.discovered_endpoints),
            'discovered_parameters': len(self.discovered_params),
            'files_with_sinks': len(self.xss_sinks),
        }

def analyze_javascript(js_urls: List[str]) -> Tuple[Set[str], Set[str], Dict]:
    """Convenience function to analyze JavaScript files"""
    analyzer = JSAnalyzer()
    return analyzer.analyze_js_files(js_urls)
