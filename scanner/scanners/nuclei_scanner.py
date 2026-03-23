"""
Nuclei integration for template-based vulnerability scanning
"""
import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path
from scanner.logger import logger
from scanner.utils import run_command, check_tool_exists
from scanner.config import (
    NUCLEI_TEMPLATES_REPO, NUCLEI_TEMPLATES_DIR, NUCLEI_TAGS,
    NUCLEI_SEVERITY, NUCLEI_TIMEOUT, PROJECT_ROOT, MAX_WORKERS
)

class NucleiScanner:
    """Integration with Nuclei templates for advanced scanning"""
    
    def __init__(self):
        self.findings = []
        self.templates_updated = False
        logger.info("NucleiScanner initialized")
    
    def ensure_templates(self) -> bool:
        """Clone/update nuclei-templates repository"""
        
        if not check_tool_exists('nuclei'):
            logger.warning("nuclei is not installed")
            return False
        
        # Check if templates exist
        if NUCLEI_TEMPLATES_DIR.exists():
            logger.info("Updating nuclei templates...")
            success, _, _ = run_command(
                f'cd {NUCLEI_TEMPLATES_DIR} && git pull',
                timeout=60
            )
            if success:
                self.templates_updated = True
                return True
        else:
            # Clone templates
            logger.info("Cloning nuclei templates...")
            success, stdout, stderr = run_command(
                f'git clone {NUCLEI_TEMPLATES_REPO} {NUCLEI_TEMPLATES_DIR}',
                timeout=120
            )
            if success:
                self.templates_updated = True
                logger.info("Templates cloned successfully")
                return True
            else:
                logger.error(f"Failed to clone templates: {stderr}")
                return False
        
        return True
    
    def scan_urls(self, urls: List[str], tags: List[str] = None, severity: List[str] = None) -> List[Dict]:
        """
        Scan URLs using Nuclei templates
        
        Args:
            urls: List of URLs to scan
            tags: Template tags to use (default: NUCLEI_TAGS)
            severity: Severity levels to report (default: NUCLEI_SEVERITY)
        
        Returns:
            List of findings
        """
        
        if not check_tool_exists('nuclei'):
            logger.warning("nuclei not available, skipping Nuclei scan")
            return []
        
        # Ensure templates are available
        if not self.ensure_templates():
            logger.warning("Could not setup Nuclei templates")
            return []
        
        tags = tags or NUCLEI_TAGS
        severity = severity or NUCLEI_SEVERITY
        
        logger.info(f"Running Nuclei scan on {len(urls)} URLs with tags: {tags}")
        
        # Build nuclei command
        tags_str = ','.join(tags)
        severity_str = ','.join(severity)
        
        # Save URLs to temp file
        urls_file = PROJECT_ROOT / 'nuclei_urls.txt'
        try:
            with open(urls_file, 'w') as f:
                f.write('\n'.join(urls))
        except Exception as e:
            logger.error(f"Error writing URLs file: {e}")
            return []
        
        try:
            # Run nuclei with JSON output
            output_file = PROJECT_ROOT / 'nuclei_output.json'
            command = (
                f'nuclei -l {urls_file} '
                f'-tags {tags_str} '
                f'-severity {severity_str} '
                f'-c {MAX_WORKERS} '
                f'-timeout {NUCLEI_TIMEOUT} '
                f'-json -o {output_file} '
                f'-rate-limit 50 '
                f'-rl 50 '
                f'-duc'  # Disable update check
            )
            
            logger.debug(f"Running: {command}")
            success, stdout, stderr = run_command(command, timeout=NUCLEI_TIMEOUT * 2)
            
            # Parse output
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    result = json.loads(line)
                                    finding = self._convert_nuclei_result(result)
                                    if finding:
                                        self.findings.append(finding)
                                except json.JSONDecodeError:
                                    pass
                except Exception as e:
                    logger.debug(f"Error reading Nuclei output: {e}")
            
            logger.info(f"Nuclei scan complete. Found {len(self.findings)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error running Nuclei: {e}")
        
        finally:
            # Cleanup
            try:
                if urls_file.exists():
                    urls_file.unlink()
                if output_file.exists():
                    output_file.unlink()
            except:
                pass
        
        return self.findings
    
    def _convert_nuclei_result(self, result: Dict) -> Dict:
        """Convert Nuclei JSON result to standard finding format"""
        
        try:
            # Map Nuclei result fields to standard format
            severity_map = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Info'}
            
            finding = {
                'type': result.get('info', {}).get('name', 'Unknown'),
                'url': result.get('matched-at', result.get('host', '')),
                'template': result.get('template-id', ''),
                'severity': severity_map.get(result.get('info', {}).get('severity', 'info'), 'Medium'),
                'description': result.get('info', {}).get('description', ''),
                'timestamp': result.get('timestamp', ''),
                'proof': result.get('curl-command', '') or result.get('extracted-results', ''),
                'metadata': result.get('info', {}).get('metadata', {}),
            }
            
            # Add reference
            if 'reference' in result.get('info', {}):
                finding['reference'] = result['info']['reference']
            
            return finding
        
        except Exception as e:
            logger.debug(f"Error converting Nuclei result: {e}")
            return None
    
    def scan_misconfigurations(self, urls: List[str]) -> List[Dict]:
        """Specialized scan for misconfigurations"""
        logger.info("Scanning for misconfigurations...")
        return self.scan_urls(urls, tags=['misconfig', 'exposure'], severity=['critical', 'high'])
    
    def scan_cves(self, urls: List[str]) -> List[Dict]:
        """Specialized scan for known CVEs"""
        logger.info("Scanning for known CVEs...")
        return self.scan_urls(urls, tags=['cve'], severity=['critical', 'high', 'medium'])
    
    def get_findings_summary(self) -> Dict:
        """Get summary of findings"""
        summary = {
            'total': len(self.findings),
            'by_severity': {},
            'by_type': {},
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown')
            finding_type = finding.get('type', 'Unknown')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
        
        return summary

def scan_with_nuclei(urls: List[str], tags: List[str] = None, severity: List[str] = None) -> List[Dict]:
    """Convenience function to scan with Nuclei"""
    scanner = NucleiScanner()
    return scanner.scan_urls(urls, tags, severity)
