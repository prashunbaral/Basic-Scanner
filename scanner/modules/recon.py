"""
Recon module: URL collection and discovery
Integrates gau, waybackurls, and katana
"""
import concurrent.futures
from typing import List, Set, Optional
from scanner.logger import logger
from scanner.utils import (
    run_command, normalize_url, deduplicate_urls, filter_urls,
    check_tool_exists, is_valid_url, chunk_list
)
from scanner.config import MAX_WORKERS, MAX_URLS, TIMEOUT

class ReconModule:
    """Handles URL discovery and collection"""
    
    def __init__(self):
        self.urls = set()
        self.wayback_urls = set()
        self.live_urls = set()
        self.js_urls = set()
        self.endpoint_urls = set()
        logger.info("ReconModule initialized")
    
    def collect_urls(self, domains: List[str]) -> Set[str]:
        """
        Collect URLs from multiple sources
        
        Args:
            domains: List of target domains
        
        Returns:
            Set of deduplicated URLs
        """
        logger.info(f"Starting URL collection for {len(domains)} domain(s)")
        
        all_urls = set()
        
        # Collect from each source
        wayback = self._collect_wayback_urls(domains)
        live = self._collect_live_urls(domains)
        
        all_urls.update(wayback)
        all_urls.update(live)
        
        # Filter and normalize
        all_urls = deduplicate_urls(list(all_urls))
        all_urls = filter_urls(list(all_urls))
        
        # Limit total URLs
        if len(all_urls) > MAX_URLS:
            logger.warning(f"Found {len(all_urls)} URLs, limiting to {MAX_URLS}")
            all_urls = set(list(all_urls)[:MAX_URLS])
        
        logger.info(f"Total unique URLs collected: {len(all_urls)}")
        self.urls = all_urls
        return all_urls
    
    def _collect_wayback_urls(self, domains: List[str]) -> Set[str]:
        """Collect URLs from Wayback Machine using gau and waybackurls"""
        logger.info("Collecting URLs from Wayback Machine...")
        wayback_urls = set()
        
        for domain in domains:
            # Try gau first
            if check_tool_exists('gau'):
                success, stdout, stderr = run_command(
                    f'gau --mc 200,301,302,307 {domain}',
                    timeout=TIMEOUT
                )
                if success and stdout:
                    urls = [line.strip() for line in stdout.split('\n') if line.strip()]
                    logger.info(f"gau found {len(urls)} URLs from {domain}")
                    wayback_urls.update(urls)
            
            # Try waybackurls as fallback
            elif check_tool_exists('waybackurls'):
                success, stdout, stderr = run_command(
                    f'echo {domain} | waybackurls',
                    timeout=TIMEOUT
                )
                if success and stdout:
                    urls = [line.strip() for line in stdout.split('\n') if line.strip()]
                    logger.info(f"waybackurls found {len(urls)} URLs from {domain}")
                    wayback_urls.update(urls)
            else:
                logger.warning("gau/waybackurls not available, skipping Wayback collection")
        
        return wayback_urls
    
    def _collect_live_urls(self, domains: List[str]) -> Set[str]:
        """Collect URLs from live scanning using katana"""
        logger.info("Collecting URLs from live crawling (katana)...")
        live_urls = set()
        
        if not check_tool_exists('katana'):
            logger.warning("katana not available, skipping live URL collection")
            return live_urls
        
        for domain in domains:
            try:
                # Use katana with appropriate flags
                success, stdout, stderr = run_command(
                    f'katana -u {domain} -depth 3 -jc -timeout 10',
                    timeout=TIMEOUT * 3
                )
                
                if success and stdout:
                    urls = [line.strip() for line in stdout.split('\n') if line.strip()]
                    logger.info(f"katana found {len(urls)} URLs from {domain}")
                    live_urls.update(urls)
                else:
                    logger.debug(f"katana scan for {domain}: {stderr}")
            except Exception as e:
                logger.warning(f"Error collecting live URLs from {domain}: {e}")
        
        return live_urls
    
    def extract_js_urls(self) -> Set[str]:
        """Extract JavaScript file URLs from collected URLs"""
        logger.info("Extracting JavaScript URLs...")
        js_urls = set()
        
        for url in self.urls:
            if url.endswith('.js') or '/js/' in url or '/javascript/' in url:
                js_urls.add(url)
        
        logger.info(f"Found {len(js_urls)} JavaScript URLs")
        self.js_urls = js_urls
        return js_urls
    
    def get_unique_endpoints(self) -> Set[str]:
        """Get unique endpoint paths for parameter testing"""
        from scanner.utils import get_unique_endpoints
        
        logger.info("Extracting unique endpoints...")
        endpoints = get_unique_endpoints(list(self.urls))
        
        logger.info(f"Found {len(endpoints)} unique endpoints")
        self.endpoint_urls = endpoints
        return endpoints
    
    def get_urls_by_pattern(self, pattern: str) -> List[str]:
        """Get URLs matching a specific pattern"""
        import re
        matching_urls = []
        
        try:
            regex = re.compile(pattern)
            for url in self.urls:
                if regex.search(url):
                    matching_urls.append(url)
        except re.error as e:
            logger.error(f"Invalid regex pattern: {e}")
            return []
        
        logger.info(f"Found {len(matching_urls)} URLs matching pattern: {pattern}")
        return matching_urls
    
    def discover_hidden_parameters(self, domains: List[str]) -> Set[str]:
        """Discover hidden parameters using paramspider"""
        logger.info("Discovering hidden parameters with paramspider...")
        
        if not check_tool_exists('paramspider'):
            logger.warning("paramspider not available, skipping parameter discovery")
            return set()
        
        discovered_params = set()
        
        for domain in domains:
            try:
                success, stdout, stderr = run_command(
                    f'paramspider -d {domain} -o /tmp/paramspider_output.txt',
                    timeout=TIMEOUT * 2
                )
                
                if success:
                    try:
                        with open('/tmp/paramspider_output.txt', 'r') as f:
                            urls = f.read().split('\n')
                            self.urls.update(filter_urls(urls))
                            logger.info(f"paramspider found {len(urls)} additional URLs")
                    except:
                        pass
            except Exception as e:
                logger.warning(f"Error running paramspider on {domain}: {e}")
        
        return discovered_params
    
    def get_summary(self) -> dict:
        """Get recon summary"""
        return {
            'total_urls': len(self.urls),
            'js_urls': len(self.js_urls),
            'unique_endpoints': len(self.endpoint_urls),
        }

def get_recon_urls(domains: List[str]) -> Set[str]:
    """Convenience function to get URLs from recon"""
    recon = ReconModule()
    urls = recon.collect_urls(domains)
    recon.extract_js_urls()
    recon.get_unique_endpoints()
    recon.discover_hidden_parameters(domains)
    return recon.urls
