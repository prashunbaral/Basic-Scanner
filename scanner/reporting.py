"""
Reporting module: Generate findings reports in multiple formats
"""
import json
import time
from typing import List, Dict
from pathlib import Path
from datetime import datetime
from scanner.logger import logger
from scanner.config import OUTPUT_DIR, SEVERITY_LEVELS
import html

class ReportGenerator:
    """Generates vulnerability reports in JSON and HTML formats"""
    
    def __init__(self, target: str):
        self.target = target
        self.findings = []
        self.start_time = time.time()
        self.scan_info = {
            'target': target,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'duration_seconds': 0,
        }
        logger.info(f"ReportGenerator initialized for target: {target}")
    
    def add_findings(self, findings: List[Dict]):
        """Add findings to report"""
        self.findings.extend(findings)
        logger.info(f"Added {len(findings)} findings to report")
    
    def finalize(self):
        """Finalize report with timing information"""
        self.scan_info['end_time'] = datetime.now().isoformat()
        self.scan_info['duration_seconds'] = time.time() - self.start_time
    
    def generate_json_report(self, filename: str = None) -> Path:
        """Generate JSON report"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{self.target.replace(':', '_').replace('/', '_')}_{timestamp}.json"
        
        filepath = OUTPUT_DIR / filename
        
        report = {
            'metadata': self.scan_info,
            'summary': self._get_summary(),
            'findings': self._sort_findings(),
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"JSON report saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving JSON report: {e}")
            return None
    
    def generate_html_report(self, filename: str = None) -> Path:
        """Generate HTML report"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{self.target.replace(':', '_').replace('/', '_')}_{timestamp}.html"
        
        filepath = OUTPUT_DIR / filename
        
        html_content = self._generate_html()
        
        try:
            with open(filepath, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML report saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving HTML report: {e}")
            return None
    
    def generate_txt_report(self, filename: str = None) -> Path:
        """Generate human-readable text report"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{self.target.replace(':', '_').replace('/', '_')}_{timestamp}.txt"
        
        filepath = OUTPUT_DIR / filename
        
        txt_content = self._generate_txt()
        
        try:
            with open(filepath, 'w') as f:
                f.write(txt_content)
            logger.info(f"Text report saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving text report: {e}")
            return None
    
    def _get_summary(self) -> Dict:
        """Generate findings summary"""
        summary = {
            'total_findings': len(self.findings),
            'by_severity': {},
            'by_type': {},
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown')
            finding_type = finding.get('type', 'Unknown')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
        
        return summary
    
    def _sort_findings(self) -> List[Dict]:
        """Sort findings by severity"""
        return sorted(
            self.findings,
            key=lambda x: SEVERITY_LEVELS.get(x.get('severity', 'info').lower(), 0),
            reverse=True
        )
    
    def _generate_html(self) -> str:
        """Generate HTML report content"""
        
        summary = self._get_summary()
        sorted_findings = self._sort_findings()
        
        severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#17a2b8',
            'Info': '#6c757d',
        }
        
        html_parts = [
            """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Vulnerability Scan Report</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        background: #f5f5f5;
                    }
                    .header {
                        background: #333;
                        color: white;
                        padding: 20px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }
                    .summary {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px;
                        margin-bottom: 30px;
                    }
                    .summary-item {
                        background: white;
                        padding: 15px;
                        border-radius: 5px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    .summary-item h3 {
                        margin: 0 0 10px 0;
                        color: #666;
                    }
                    .summary-item .number {
                        font-size: 28px;
                        font-weight: bold;
                        color: #333;
                    }
                    .finding {
                        background: white;
                        padding: 15px;
                        margin-bottom: 15px;
                        border-left: 5px solid #ccc;
                        border-radius: 3px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    .severity-critical { border-left-color: #dc3545; background: #fff5f5; }
                    .severity-high { border-left-color: #fd7e14; background: #fff9f5; }
                    .severity-medium { border-left-color: #ffc107; background: #fffbf5; }
                    .severity-low { border-left-color: #17a2b8; background: #f5fbff; }
                    .severity-info { border-left-color: #6c757d; background: #f8f9fa; }
                    .finding h4 {
                        margin: 0 0 10px 0;
                    }
                    .finding-meta {
                        display: grid;
                        grid-template-columns: repeat(2, 1fr);
                        gap: 10px;
                        margin: 10px 0;
                        font-size: 14px;
                    }
                    .finding-meta-item {
                        color: #666;
                    }
                    .finding-meta-label {
                        font-weight: bold;
                        color: #333;
                    }
                    .badge {
                        display: inline-block;
                        padding: 4px 8px;
                        border-radius: 3px;
                        font-size: 12px;
                        font-weight: bold;
                        color: white;
                    }
                    .poc-link {
                        color: #0066cc;
                        text-decoration: none;
                        word-break: break-all;
                    }
                    .poc-link:hover {
                        text-decoration: underline;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                    }
                    th, td {
                        padding: 10px;
                        text-align: left;
                        border-bottom: 1px solid #ddd;
                    }
                    th {
                        background: #f5f5f5;
                        font-weight: bold;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Vulnerability Scan Report</h1>
                    <p><strong>Target:</strong> """ + html.escape(str(self.target)) + """</p>
                    <p><strong>Scan Time:</strong> """ + self.scan_info['start_time'] + """</p>
                    <p><strong>Duration:</strong> """ + f"{self.scan_info['duration_seconds']:.1f}s" + """</p>
                </div>
            """
        ]
        
        # Summary section
        html_parts.append('<div class="summary">')
        html_parts.append(f"""
            <div class="summary-item">
                <h3>Total Findings</h3>
                <div class="number">{summary['total_findings']}</div>
            </div>
        """)
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = summary['by_severity'].get(severity, 0)
            html_parts.append(f"""
                <div class="summary-item">
                    <h3>{severity}</h3>
                    <div class="number" style="color: {severity_colors.get(severity, '#999')};">{count}</div>
                </div>
            """)
        
        html_parts.append('</div>')
        
        # Findings section
        html_parts.append('<h2>Detailed Findings</h2>')
        
        if not sorted_findings:
            html_parts.append('<p style="color: #666;">No vulnerabilities found.</p>')
        else:
            for finding in sorted_findings:
                severity = finding.get('severity', 'Unknown')
                finding_type = finding.get('type', 'Unknown')
                
                html_parts.append(f"""
                    <div class="finding severity-{severity.lower()}">
                        <h4>{html.escape(str(finding_type))} <span class="badge" style="background: {severity_colors.get(severity, '#999')};">{severity}</span></h4>
                        <div class="finding-meta">
                            <div class="finding-meta-item">
                                <span class="finding-meta-label">URL:</span> <code>{html.escape(str(finding.get('url', 'N/A')))}</code>
                            </div>
                            <div class="finding-meta-item">
                                <span class="finding-meta-label">Parameter:</span> {html.escape(str(finding.get('parameter', 'N/A')))}
                            </div>
                            <div class="finding-meta-item">
                                <span class="finding-meta-label">Proof:</span> {html.escape(str(finding.get('proof', 'N/A'))[:200])}
                            </div>
                        </div>
                """)
                
                # Add PoC link if available
                if 'poc_url' in finding:
                    html_parts.append(f"""
                        <p><strong>PoC URL:</strong><br>
                        <a href="{html.escape(str(finding['poc_url']))}" class="poc-link" target="_blank">{html.escape(str(finding['poc_url']))}</a>
                        </p>
                    """)
                
                html_parts.append('</div>')
        
        html_parts.append('</body></html>')
        
        return '\n'.join(html_parts)
    
    def _generate_txt(self) -> str:
        """Generate text report content"""
        
        summary = self._get_summary()
        sorted_findings = self._sort_findings()
        
        lines = [
            '=' * 80,
            'VULNERABILITY SCAN REPORT',
            '=' * 80,
            '',
            f'Target: {self.target}',
            f'Scan Date: {self.scan_info["start_time"]}',
            f'Duration: {self.scan_info["duration_seconds"]:.1f} seconds',
            '',
            '=' * 80,
            'SUMMARY',
            '=' * 80,
            f'Total Findings: {summary["total_findings"]}',
            '',
            'By Severity:',
        ]
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = summary['by_severity'].get(severity, 0)
            lines.append(f'  {severity}: {count}')
        
        lines.extend(['', 'By Type:'])
        
        for finding_type, count in sorted(summary['by_type'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f'  {finding_type}: {count}')
        
        lines.extend(['', '=' * 80, 'DETAILED FINDINGS', '=' * 80, ''])
        
        if not sorted_findings:
            lines.append('No vulnerabilities found.')
        else:
            for i, finding in enumerate(sorted_findings, 1):
                lines.extend([
                    f'[{i}] {finding.get("type", "Unknown")} ({finding.get("severity", "Unknown")})',
                    f'URL: {finding.get("url", "N/A")}',
                    f'Parameter: {finding.get("parameter", "N/A")}',
                    f'Proof: {finding.get("proof", "N/A")}',
                ])
                
                if 'poc_url' in finding:
                    lines.append(f'PoC URL: {finding["poc_url"]}')
                
                if 'payload' in finding:
                    lines.append(f'Payload: {finding["payload"][:100]}')
                
                lines.append('')
        
        lines.extend([
            '=' * 80,
            'END OF REPORT',
            '=' * 80,
        ])
        
        return '\n'.join(lines)

def generate_reports(target: str, findings_by_scanner: Dict[str, List[Dict]]) -> Dict[str, Path]:
    """Generate all report formats"""
    
    generator = ReportGenerator(target)
    
    # Collect all findings
    for scanner_name, findings in findings_by_scanner.items():
        generator.add_findings(findings)
        logger.info(f"Added findings from {scanner_name}: {len(findings)}")
    
    generator.finalize()
    
    # Generate reports
    reports = {
        'json': generator.generate_json_report(),
        'html': generator.generate_html_report(),
        'txt': generator.generate_txt_report(),
    }
    
    logger.info(f"Generated reports: {reports}")
    return reports
