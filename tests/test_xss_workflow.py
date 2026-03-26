import io
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import main
from scanner.scanner_engine import VulnerabilityScanner
from scanner.scanners.xss import scan_xss


class HtmlInjectionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.scanner = VulnerabilityScanner('https://example.com', silent=True)

    def test_verify_html_injection_detects_new_markup(self):
        baseline = '<html><body><p>superman</p></body></html>'
        injected = '<html><body><p><s data-superman="superman">superman</s></p></body></html>'
        self.assertTrue(self.scanner._verify_html_injection(baseline, injected, 'html_markup'))

    @patch('scanner.scanner_engine.run_playwright_dom_verification')
    def test_apply_confidence_promotes_when_browser_verifies(self, mock_verify):
        mock_verify.return_value = {
            'verified': True,
            'matched_selector': 's[data-superman="superman"]',
            'error': None,
        }
        finding = {
            'type': 'HTML Injection',
            'status': 'HTML_INJECTION',
            'proof': 'Parsed HTML changed in html_text context',
        }
        updated = self.scanner._apply_confidence(
            finding,
            base_confidence='medium',
            test_url='https://example.com/?q=%3Cs%20data-superman%3D%22superman%22%3Esuperman%3C/s%3E',
            probe_type='html_markup',
            proof_prefix='Parsed HTML changed in html_text context',
        )
        self.assertEqual(updated['confidence'], 'high')
        self.assertTrue(updated['browser_verified'])
        self.assertIn('Playwright verified', updated['proof'])

    @patch('scanner.scanner_engine.run_playwright_dom_verification')
    def test_apply_confidence_keeps_medium_when_browser_not_verified(self, mock_verify):
        mock_verify.return_value = {'verified': False, 'matched_selector': None, 'error': None}
        finding = {'type': 'HTML Injection', 'status': 'HTML_INJECTION', 'proof': 'Parsed HTML changed'}
        updated = self.scanner._apply_confidence(
            finding,
            base_confidence='medium',
            test_url='https://example.com/?q=test',
            probe_type='html_markup',
            proof_prefix='Parsed HTML changed',
        )
        self.assertEqual(updated['confidence'], 'medium')
        self.assertNotIn('browser_verified', updated)


class SilentModeOutputTests(unittest.TestCase):
    @patch('scanner.scanner_engine.VulnerabilityScanner.__init__', return_value=None)
    @patch('scanner.scanner_engine.VulnerabilityScanner.scan')
    def test_silent_mode_outputs_only_findings(self, mock_scan, _mock_init):
        mock_scan.return_value = [{
            'type': 'HTML Injection',
            'status': 'HTML_INJECTION',
            'url': 'https://example.com',
            'test_url': 'https://example.com/?q=%3E%3Cs%20data-superman%3D%22superman%22%3Esuperman%3C/s%3E',
            'parameter': 'q',
            'payload_type': 'html_markup',
            'confidence': 'high',
        }]

        buf = io.StringIO()
        with patch('sys.argv', ['main.py', 'https://example.com', '--silent']), redirect_stdout(buf):
            main.main()

        output = buf.getvalue().strip().splitlines()
        self.assertEqual(len(output), 1)
        self.assertIn('[HTML_INJECTION]', output[0])
        self.assertIn('confidence=high', output[0])

    @patch('scanner.scanner_engine.VulnerabilityScanner.__init__', return_value=None)
    @patch('scanner.scanner_engine.VulnerabilityScanner.scan', return_value=[])
    def test_silent_mode_outputs_nothing_without_findings(self, _mock_scan, _mock_init):
        buf = io.StringIO()
        with patch('sys.argv', ['main.py', 'https://example.com', '--silent']), redirect_stdout(buf):
            main.main()
        self.assertEqual(buf.getvalue(), '')

    @patch('scanner.scanner_engine.VulnerabilityScanner.scan')
    @patch('scanner.scanner_engine.VulnerabilityScanner.__init__', return_value=None)
    def test_batch_non_silent_shows_per_host_stats(self, _mock_init, mock_scan):
        mock_scan.return_value = []
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write('example.com\n')
            tmp_path = tmp.name

        args = main.argparse.Namespace(
            subdomains=tmp_path,
            silent=False,
            deep=False,
            aggressive=False,
            bypass_waf=False,
            xss_verbose=False,
            nuclei=False,
            nuclei_cves=False,
            update_nuclei_templates=False,
            update_nuclei=False,
            discovery_cache=None,
            threads=10,
            timeout=0,
            xss_only=True,
            xss_nuclei=False,
            sql_only=False,
            ssrf_only=False,
            xxe_only=False,
            nuclei_only=False,
            path_xss=False,
            custom_param=False,
            sqlmap=False,
            param_discovery=False,
            all=False,
            json=None,
            output=None,
        )

        def init_side_effect(self, *args, **kwargs):
            self.discovered_urls = ['https://example.com/a', 'https://example.com/b']
            self.discovered_param_records = [{'name': 'q'}, {'name': 'id'}]
            self.discovery_output_dir = '/tmp/discovery'
            self.discovery_source_counts = {
                'gau': {'urls': 2, 'params': 1},
                'katana': {'urls': 1, 'params': 1},
            }

        with patch('scanner.scanner_engine.VulnerabilityScanner.__init__', new=init_side_effect):
            buf = io.StringIO()
            with redirect_stdout(buf):
                main.scan_subdomains_batch(args)
        output = buf.getvalue()
        self.assertIn('done | findings=0 | printed=0 | discovered_urls=2 | discovered_params=2 | scans=xss', output)
        self.assertIn('sources=gau:u2/p1,katana:u1/p1', output)
        self.assertIn('cache=/tmp/discovery', output)
        self.assertIn('Found 0 raw findings, printed 0 findings', output)

    @patch('scanner.scanner_engine.VulnerabilityScanner.scan', return_value=[])
    def test_batch_silent_shows_no_progress_lines(self, mock_scan):
        with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
            tmp.write('example.com\n')
            tmp_path = tmp.name

        args = main.argparse.Namespace(
            subdomains=tmp_path,
            silent=True,
            deep=False,
            aggressive=False,
            bypass_waf=False,
            xss_verbose=False,
            nuclei=False,
            nuclei_cves=False,
            update_nuclei_templates=False,
            update_nuclei=False,
            discovery_cache=None,
            threads=10,
            timeout=0,
            xss_only=True,
            xss_nuclei=False,
            sql_only=False,
            ssrf_only=False,
            xxe_only=False,
            nuclei_only=False,
            path_xss=False,
            custom_param=False,
            sqlmap=False,
            param_discovery=False,
            all=False,
            json=None,
            output=None,
        )

        def init_side_effect(self, *args, **kwargs):
            self.discovered_urls = ['https://example.com/a']
            self.discovered_param_records = [{'name': 'q'}]
            self.discovery_output_dir = '/tmp/discovery'
            self.discovery_source_counts = {'gau': {'urls': 1, 'params': 1}}

        with patch('scanner.scanner_engine.VulnerabilityScanner.__init__', new=init_side_effect):
            buf = io.StringIO()
            with redirect_stdout(buf):
                main.scan_subdomains_batch(args)
        output = buf.getvalue()
        self.assertNotIn('Scanning https://example.com', output)
        self.assertNotIn('done | findings=', output)


class CompatibilityShimTests(unittest.TestCase):
    @patch('scanner.scanner_engine.VulnerabilityScanner.scan')
    def test_legacy_scan_xss_delegates_to_main_engine(self, mock_scan):
        mock_scan.return_value = [{'type': 'HTML Injection', 'status': 'HTML_INJECTION'}]
        findings = scan_xss(['https://example.com/?q=superman'])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'HTML Injection')


if __name__ == '__main__':
    unittest.main()
