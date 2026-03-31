"""
Playwright-based browser automation for crawling and targeted DOM verification.
"""

import asyncio
import logging
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse, parse_qs
import re

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class PlaywrightSpider:
    """Crawl target website using Playwright headless browser to discover parameters from navigation"""
    
    def __init__(self, timeout: int = 30, max_pages: int = 50, verbose: bool = False, silent: bool = False):
        """
        Args:
            timeout: Request timeout in seconds
            max_pages: Maximum pages to crawl
            verbose: Enable debug logging
            silent: Suppress all logging
        """
        self.timeout = timeout * 1000  # Convert to milliseconds
        self.max_pages = max_pages
        self.verbose = verbose
        self.silent = silent
        self.logger = logging.getLogger(__name__)
        self.visited_urls: Set[str] = set()
        self.discovered_parameters: Set[str] = set()
        self.discovered_urls: List[str] = []
        
    async def crawl(self, start_url: str, headless: bool = True) -> Dict[str, any]:
        """
        Crawl website using Playwright browser
        
        Args:
            start_url: Starting URL to crawl from
            headless: Run browser in headless mode
            
        Returns:
            Dict with discovered URLs and parameters
        """
        if not PLAYWRIGHT_AVAILABLE:
            if not self.silent:
                self.logger.error("Playwright not installed. Install with: pip install playwright && python -m playwright install chromium")
            return {"urls": [], "parameters": []}
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=headless)
                context = await browser.new_context()
                page = await context.new_page()
                
                # Set timeout
                page.set_default_timeout(self.timeout)
                page.set_default_navigation_timeout(self.timeout)
                
                # Navigate to start URL
                try:
                    if not self.silent:
                        self.logger.info(f"🌐 Starting Playwright crawl from {start_url}")
                    await page.goto(start_url, wait_until='load')
                except Exception as e:
                    if not self.silent:
                        self.logger.warning(f"Failed to load {start_url}: {e}")
                
                # Crawl the site
                await self._crawl_recursive(page, start_url)
                
                await browser.close()
        
        except Exception as e:
            if not self.silent:
                self.logger.error(f"Playwright error: {e}")
            else:
                self.logger.debug(f"Playwright error (silent mode): {e}")
        
        return {
            "urls": list(self.discovered_urls),
            "parameters": list(self.discovered_parameters),
            "total_urls": len(self.discovered_urls),
            "total_parameters": len(self.discovered_parameters),
        }
    
    async def _crawl_recursive(self, page, url: str, depth: int = 0, max_depth: int = 3):
        """Recursively crawl pages on the site"""
        
        if len(self.visited_urls) >= self.max_pages:
            self.logger.info(f"Reached max pages limit ({self.max_pages})")
            return
        
        if depth > max_depth:
            return
        
        # Normalize URL
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if normalized in self.visited_urls:
            return
        
        self.visited_urls.add(normalized)
        self.discovered_urls.append(url)
        
        self.logger.info(f"🔗 Crawling [{len(self.visited_urls)}/{self.max_pages}]: {url}")
        
        try:
            # Extract parameters from current URL
            self._extract_parameters_from_url(url)
            
            # Get all links on the page
            links = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter((url, idx, arr) => arr.indexOf(url) === idx)
                        .slice(0, 20);
                }
            """)
            
            # Click on form inputs to discover parameters
            form_params = await page.evaluate("""
                () => {
                    const params = new Set();
                    document.querySelectorAll('input, textarea, select').forEach(el => {
                        if (el.name) params.add(el.name);
                        if (el.id) params.add(el.id);
                    });
                    return Array.from(params);
                }
            """)
            
            for param in form_params:
                if param:
                    self.discovered_parameters.add(param)
                    self.logger.debug(f"  Found parameter: {param}")
            
            # Visit discovered links
            for link in links:
                if len(self.visited_urls) >= self.max_pages:
                    break
                
                try:
                    link_parsed = urlparse(link)
                    link_base = f"{link_parsed.scheme}://{link_parsed.netloc}"
                    
                    # Only crawl same domain
                    if link_base != base_url:
                        continue
                    
                    # Skip certain file types
                    if any(link.endswith(ext) for ext in ['.jpg', '.png', '.gif', '.css', '.js', '.pdf']):
                        continue
                    
                    # Extract parameters from link
                    self._extract_parameters_from_url(link)
                    
                    # Navigate to link
                    if link not in self.visited_urls:
                        try:
                            await page.goto(link, wait_until='load')
                            await self._crawl_recursive(page, link, depth + 1, max_depth)
                        except Exception as e:
                            self.logger.debug(f"Failed to navigate to {link}: {e}")
                
                except Exception as e:
                    self.logger.debug(f"Error processing link {link}: {e}")
        
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")
    
    def _extract_parameters_from_url(self, url: str):
        """Extract parameters from URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params.keys():
                if param:
                    self.discovered_parameters.add(param)
                    self.logger.debug(f"  Found parameter: {param}")
        except Exception as e:
            self.logger.debug(f"Error parsing URL {url}: {e}")


async def verify_playwright_dom(
    url: str,
    selectors: List[str],
    timeout: int = 30,
    silent: bool = False
) -> Dict[str, any]:
    """
    Load a page and check whether any selector is present in the rendered DOM.

    Returns:
        {
            "verified": bool,
            "matched_selector": str | None,
            "error": str | None,
        }
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {"verified": False, "matched_selector": None, "error": "Playwright not installed"}

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            page.set_default_timeout(timeout * 1000)
            page.set_default_navigation_timeout(timeout * 1000)

            try:
                await page.goto(url, wait_until='load')
            except Exception:
                await page.goto(url, wait_until='domcontentloaded')

            matched_selector = None
            for selector in selectors:
                try:
                    handle = await page.query_selector(selector)
                    if handle is not None:
                        matched_selector = selector
                        break
                except Exception:
                    continue

            await browser.close()
            return {
                "verified": matched_selector is not None,
                "matched_selector": matched_selector,
                "error": None,
            }
    except Exception as e:
        if not silent:
            logging.debug(f"Playwright DOM verification error: {e}")
        return {"verified": False, "matched_selector": None, "error": str(e)}


def run_playwright_spider(url: str, timeout: int = 30, max_pages: int = 50, verbose: bool = False, silent: bool = False) -> Dict:
    """
    Synchronous wrapper for Playwright spider
    
    Args:
        url: URL to start crawling from
        timeout: Request timeout
        max_pages: Maximum pages to crawl
        verbose: Enable verbose logging
        silent: Suppress all logging
        
    Returns:
        Dict with discovered URLs and parameters
    """
    spider = PlaywrightSpider(timeout=timeout, max_pages=max_pages, verbose=verbose, silent=silent)
    
    try:
        # Run async crawler
        result = asyncio.run(spider.crawl(url, headless=True))
        return result
    except Exception as e:
        if not silent:
            logging.error(f"Playwright spider error: {e}")
        else:
            logging.debug(f"Playwright spider error (silent mode): {e}")
        return {"urls": [], "parameters": []}


def run_playwright_dom_verification(url: str, selectors: List[str], timeout: int = 30, silent: bool = False) -> Dict:
    """Synchronous wrapper for DOM verification."""
    try:
        return asyncio.run(verify_playwright_dom(url, selectors, timeout=timeout, silent=silent))
    except Exception as e:
        if not silent:
            logging.debug(f"Playwright DOM verification wrapper error: {e}")
        return {"verified": False, "matched_selector": None, "error": str(e)}
