"""
Compatibility shim for the legacy XSS scanner module.

The duplicate standalone implementation was retired in favor of the
active logic inside scanner.scanner_engine.VulnerabilityScanner.
"""

from typing import Dict, List

from scanner.scanner_engine import VulnerabilityScanner


class XSSScanner:
    """Compatibility wrapper that delegates to the main scanner engine."""

    def __init__(self, **scanner_kwargs):
        self.scanner_kwargs = scanner_kwargs

    def scan_urls(self, urls: List[str]) -> List[Dict]:
        findings: List[Dict] = []
        for url in urls:
            scanner = VulnerabilityScanner(
                target_url=url,
                silent=self.scanner_kwargs.get('silent', True),
                verbose=self.scanner_kwargs.get('verbose', False),
                xss_verbose=self.scanner_kwargs.get('xss_verbose', False),
            )
            findings.extend(scanner.scan(scan_types=['xss']))
        return findings

    def scan_stored_xss_sinks(self, sinks: Dict[str, List[str]]) -> List[Dict]:
        findings = []
        for js_url, sink_list in sinks.items():
            if not sink_list:
                continue
            findings.append({
                'type': 'XSS (Potential Stored)',
                'status': 'POTENTIAL',
                'url': js_url,
                'severity': 'High',
                'confidence': 'medium',
                'sinks': sink_list,
                'parameter': 'N/A (JS sink)',
                'proof': f"Found {len(sink_list)} potential XSS sink(s) in JavaScript",
            })
        return findings

    def get_findings_summary(self) -> Dict:
        return {}

    def get_poc_urls(self) -> List[str]:
        return []


def scan_xss(urls: List[str]) -> List[Dict]:
    """Compatibility helper that delegates to the main scanner engine."""
    return XSSScanner().scan_urls(urls)
