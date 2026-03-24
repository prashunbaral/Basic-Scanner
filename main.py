#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Effective vulnerability discovery tool for bug bounty and pentesting

Usage:
    python main.py https://example.com
    python main.py https://example.com/search?q=test
    python main.py https://example.com --param q --deep
    python main.py https://example.com --sql-only --verbose
    python main.py https://example.com --xss-only --threads 20
"""

import argparse
import sys
import logging
import os
from pathlib import Path
from scanner.logger import logger
from scanner.utils import is_valid_url


def determine_scan_types(args):
    """Determine which scan types to run based on command-line arguments"""
    scan_types = []
    if args.xss_only:
        scan_types = ['xss']
    elif args.xss_nuclei:
        scan_types = ['xss', 'nuclei']
    elif args.sql_only:
        scan_types = ['sqli']
    elif args.ssrf_only:
        scan_types = ['ssrf']
    elif args.xxe_only:
        scan_types = ['xxe']
    elif args.nuclei_only:
        scan_types = ['nuclei']
    else:
        # Default: include all methods
        scan_types = ['xss', 'sqli', 'ssrf', 'nuclei']
        
        # Add enhanced scanning methods based on flags
        if args.path_xss:
            scan_types.append('path-xss')
        if args.custom_param:
            scan_types.append('custom-param')
        if args.sqlmap:
            scan_types.append('sqlmap')
        if args.param_discovery:
            scan_types.append('param-discovery')
        
        # Deep mode automatically enables path-based XSS, sqlmap, and XXE
        if args.deep and 'path-xss' not in scan_types:
            scan_types.append('path-xss')
        if args.deep and 'xxe' not in scan_types:
            scan_types.append('xxe')
        
        # Aggressive mode enables parameter discovery and XXE
        if args.aggressive and 'param-discovery' not in scan_types:
            scan_types.append('param-discovery')
        if args.aggressive and 'xxe' not in scan_types:
            scan_types.append('xxe')
    
    return scan_types


def scan_subdomains_batch(args):
    """Scan multiple subdomains from a file"""
    # Setup logging for batch mode
    if args.silent:
        logger.setLevel(logging.CRITICAL)
    
    # Handle file path - convert to absolute if relative
    subdomains_file = args.subdomains
    if not os.path.isabs(subdomains_file):
        subdomains_file = os.path.abspath(subdomains_file)
    
    try:
        with open(subdomains_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Subdomains file not found: {subdomains_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading subdomains file: {e}")
        sys.exit(1)
    
    if not subdomains:
        print("❌ No subdomains found in file")
        sys.exit(1)
    
    if args.silent:
        print(f"Scan begun: {len(subdomains)} subdomains")
    else:
        print(f"🔍 Starting batch scan of {len(subdomains)} subdomains")
        # Show actual flags being used
        actual_flags = []
        if args.deep:
            actual_flags.append('--deep')
        if args.aggressive:
            actual_flags.append('--aggressive')
        if args.bypass_waf:
            actual_flags.append('--bypass-waf')
        if args.xss_verbose:
            actual_flags.append('--xss-verbose')
        actual_flags.append(f'--threads {args.threads}')
        actual_flags.append(f'--timeout {args.timeout}')
        print(f"Flags: {' '.join(actual_flags)}\n")
    
    all_findings = []
    domain_param_seen = set()  # Track (domain, param) pairs to avoid duplicates
    
    for i, subdomain in enumerate(subdomains, 1):
        # Ensure subdomain has protocol
        if not subdomain.startswith(('http://', 'https://')):
            url = f'https://{subdomain}'
        else:
            url = subdomain
        
        if not args.silent:
            print(f"[{i}/{len(subdomains)}] Scanning {url}...")
        
        # Create a temporary args object for this subdomain
        from scanner.scanner_engine import VulnerabilityScanner
        
        scanner = VulnerabilityScanner(
            target_url=url,
            threads=args.threads,
            timeout=args.timeout,
            deep=args.deep,
            aggressive=args.aggressive,
            bypass_waf=args.bypass_waf,
            verbose=False,
            silent=True,  # Always silent for batch
            live_output=False,
            xss_verbose=args.xss_verbose
        )
        
        # Run scan with the appropriate scan types based on flags
        scan_types = determine_scan_types(args)
        findings = scanner.scan(param=None, scan_types=scan_types)
        
        if findings:
            for finding in findings:
                finding['subdomain'] = subdomain
                all_findings.append(finding)
                
                # Debug: Log the complete finding for diagnostics
                param = finding.get('parameter', 'UNKNOWN_PARAM')
                test_url = finding.get('test_url', '')
                payload = finding.get('payload', '')
                payload_type = finding.get('payload_type', 'unknown')
                base_url = finding.get('url', subdomain)
                
                # Deduplication: track (domain, parameter) pairs
                domain_base = base_url.split('?')[0].split('#')[0]
                dedup_key = f"{domain_base}:{param}"
                
                # Only print if we haven't seen this exact (domain, parameter) pair before
                if dedup_key not in domain_param_seen:
                    domain_param_seen.add(dedup_key)
                    
                    # Show the actual test URL if it exists, otherwise construct it
                    if test_url and '?' in test_url:
                        display_url = test_url
                    else:
                        # Fallback: construct the URL with parameter
                        display_url = f"{base_url}?{param}={payload}"
                    
                    print(f"[INJECTABLE] {display_url} | param={param} | type={payload_type}")
    
    # Print summary
    if args.silent:
        print(f"Scan ended: found {len(all_findings)} vulnerabilities across {len(subdomains)} subdomains")
    else:
        print(f"\n{'='*70}")
        print(f"✅ Batch scan complete - Found {len(all_findings)} vulnerabilities across {len(subdomains)} subdomains")
        print(f"{'='*70}\n")
    
    # Save results if requested
    if args.json and all_findings:
        _save_json_report(args.json, all_findings, f"Batch scan of {len(subdomains)} subdomains")
    
    if args.output and all_findings:
        _save_text_report(args.output, all_findings, f"Batch scan of {len(subdomains)} subdomains")
    
    return len(all_findings)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Web Vulnerability Scanner - Effective bug discovery tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan target URL
  python main.py https://example.com

  # Scan specific parameter
  python main.py https://example.com/search?q=test --param q

  # XSS only, aggressive scanning
  python main.py https://example.com --xss-only --deep --threads 20

  # SQL injection only with verbose output
  python main.py https://example.com/user?id=123 --sql-only -v

  # Scan with WAF bypass techniques
  python main.py https://example.com --bypass-waf --aggressive

  # All vulnerability types with multiple threads
  python main.py https://example.com --all --threads 15

  # Show results in real-time
  python main.py https://example.com --live
        """
    )
    
    # Positional argument: target URL
    parser.add_argument('url', nargs='?', default=None, help='Target URL to scan (e.g., https://example.com or https://example.com/page?id=1)')
    
    # Scanning options
    parser.add_argument('--subdomains', type=str, help='File containing list of subdomains to scan (one per line)')
    parser.add_argument('--xss-only', action='store_true', help='Scan for XSS vulnerabilities only')
    parser.add_argument('--xss-nuclei', action='store_true', help='Scan for XSS and Nuclei templates only')
    parser.add_argument('--sql-only', action='store_true', help='Scan for SQL Injection only')
    parser.add_argument('--ssrf-only', action='store_true', help='Scan for SSRF only')
    parser.add_argument('--xxe-only', action='store_true', help='Scan for XXE vulnerabilities only')
    parser.add_argument('--nuclei-only', action='store_true', help='Use Nuclei templates only')
    parser.add_argument('--path-xss', action='store_true', help='Test XSS in URL path segments')
    parser.add_argument('--custom-param', action='store_true', help='Test custom parameter injection')
    parser.add_argument('--sqlmap', action='store_true', help='Use sqlmap for SQL injection testing')
    parser.add_argument('--param-discovery', action='store_true', help='Discover parameters using external tools')
    parser.add_argument('--all', action='store_true', help='Scan for all vulnerability types (default)')
    
    # Advanced options
    parser.add_argument('--param', help='Specific parameter to test (default: all)')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=0, help='Request timeout in seconds (0 = unlimited, default: 0)')
    parser.add_argument('--deep', action='store_true', help='Deep scanning - test more payloads, include path-based and sqlmap')
    parser.add_argument('--aggressive', action='store_true', help='Aggressive mode - ignore rate limits, discover parameters')
    parser.add_argument('--bypass-waf', action='store_true', help='Use WAF bypass techniques')
    parser.add_argument('--xss-verbose', action='store_true', help='Test with dangerous XSS payloads (use with specific URLs containing parameters)')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--silent', action='store_true', help='Silent mode - only show findings, suppress scanning info messages')
    parser.add_argument('--live', action='store_true', help='Show results in real-time (no report file)')
    parser.add_argument('--json', help='Save results to JSON file')
    parser.add_argument('-o', '--output', help='Output directory for reports')
    
    # Validation
    parser.add_argument('--validate', action='store_true', help='Validate environment and exit')
    
    args = parser.parse_args()
    
    # Check if scanning subdomains or single URL
    if args.subdomains:
        return scan_subdomains_batch(args)
    
    # Validate URL
    if not args.url:
        print("❌ URL required (or use --subdomains for batch scanning)")
        sys.exit(1)
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    from scanner.utils import is_valid_url
    if not is_valid_url(args.url):
        print("❌ Invalid URL format")
        sys.exit(1)
    
    # Setup logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.silent:
        logger.setLevel(logging.CRITICAL)
    
    # Create scanner
    from scanner.scanner_engine import VulnerabilityScanner
    
    scanner = VulnerabilityScanner(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        deep=args.deep,
        aggressive=args.aggressive,
        bypass_waf=args.bypass_waf,
        verbose=args.verbose,
        silent=args.silent,
        live_output=args.live,
        xss_verbose=args.xss_verbose
    )
    
    if args.validate:
        if scanner.validate_environment():
            print("✅ Environment validation successful")
        else:
            print("❌ Environment validation failed")
            sys.exit(1)
        return
    
    # Determine what to scan based on flags
    scan_types = determine_scan_types(args)
    
    # Run scan
    if args.silent:
        print(f"Scan begun: {args.url}")
    else:
        print(f"\n{'='*70}")
        print(f"🔍 Scanning: {args.url}")
        print(f"{'='*70}\n")
    
    findings = scanner.scan(
        param=args.param,
        scan_types=scan_types
    )
    
    # Output results
    if findings:
        if args.silent:
            pass
        else:
            print(f"\n{'='*70}")
            print(f"✅ Found {len(findings)} vulnerability/ies")
            print(f"{'='*70}\n")
        # Always show findings details, regardless of silent mode
        for finding in findings:
            _print_finding(finding, silent=args.silent)
        if args.silent:
            print(f"Scan ended: found {len(findings)} vulnerabilities")
    else:
        # Show scan summary even if no findings
        if args.silent:
            print(f"Scan ended: no vulnerabilities found")
        else:
            print(f"\n{'='*70}")
            print(f"✅ Scan completed - No vulnerabilities found")
            print(f"{'='*70}")
            print(f"  Target: {args.url}")
            print(f"  URLs discovered: {len(scanner.discovered_urls)}")
            print(f"  Scan types: {', '.join(scan_types)}")
            print()
    
    if args.json and findings:
        _save_json_report(args.json, findings, args.url)
    
    if args.output and findings:
        _save_text_report(args.output, findings, args.url)
    
    return len(findings)


def _print_finding(finding, silent=False):
    """Pretty print a single finding"""
    if silent:
        # Silent mode: show the actual injected URL with parameter and what was injected
        param = finding.get('parameter', 'UNKNOWN_PARAM')
        test_url = finding.get('test_url', '')
        payload = finding.get('payload', '')
        payload_type = finding.get('payload_type', 'unknown')
        base_url = finding.get('url', 'N/A')
        
        # Show the actual test URL if it exists, otherwise construct it
        if test_url and '?' in test_url:
            display_url = test_url
        else:
            display_url = f"{base_url}?{param}={payload}"
        
        print(f"[INJECTABLE] {display_url} | param={param} | type={payload_type}")
    else:
        # Normal mode: detailed output
        severity_colors = {
            'Critical': '\033[91m',  # Bright red
            'High': '\033[93m',      # Yellow
            'Medium': '\033[94m',    # Blue
            'Low': '\033[92m',       # Green
        }
        reset = '\033[0m'
        
        color = severity_colors.get(finding.get('severity', 'Info'), '')
        
        print(f"{color}[{finding.get('severity', 'Info').upper()}]{reset} {finding.get('type', 'Unknown')}")
        # Use test_url (with payload) if available, otherwise fall back to base url
        display_url = finding.get('test_url') or finding.get('url', 'N/A')
        print(f"  URL: {display_url}")
        print(f"  Parameter: {finding.get('parameter', 'N/A')}")
        print(f"  Payload: {finding.get('payload', 'N/A')}")
        if 'poc_url' in finding:
            print(f"  PoC: {finding['poc_url']}")
        print(f"  Proof: {finding.get('proof', 'N/A')[:150]}")
        print()


def _save_json_report(filepath, findings, target):
    """Save findings to JSON"""
    import json
    from datetime import datetime
    
    report = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'total_findings': len(findings),
        'findings': findings
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"✅ Results saved to: {filepath}")
    except Exception as e:
        print(f"❌ Error saving JSON: {e}")


def _save_text_report(output_dir, findings, target):
    """Save findings to text file"""
    from datetime import datetime
    import os
    
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"findings_{timestamp}.txt")
    
    try:
        with open(filepath, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Scan Time: {datetime.now().isoformat()}\n")
            f.write(f"Total Findings: {len(findings)}\n")
            f.write("="*70 + "\n\n")
            
            for i, finding in enumerate(findings, 1):
                f.write(f"[{i}] {finding.get('type', 'Unknown')} ({finding.get('severity', 'Unknown')})\n")
                f.write(f"    URL: {finding.get('url', 'N/A')}\n")
                f.write(f"    Parameter: {finding.get('parameter', 'N/A')}\n")
                f.write(f"    Proof: {finding.get('proof', 'N/A')}\n")
                if 'poc_url' in finding:
                    f.write(f"    PoC: {finding['poc_url']}\n")
                f.write("\n")
        
        print(f"✅ Report saved to: {filepath}")
    except Exception as e:
        print(f"❌ Error saving report: {e}")

if __name__ == '__main__':
    main()
