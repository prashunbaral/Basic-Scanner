import io
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


class CompatibilityShimTests(unittest.TestCase):
    @patch('scanner.scanner_engine.VulnerabilityScanner.scan')
    def test_legacy_scan_xss_delegates_to_main_engine(self, mock_scan):
        mock_scan.return_value = [{'type': 'HTML Injection', 'status': 'HTML_INJECTION'}]
        findings = scan_xss(['https://example.com/?q=superman'])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'HTML Injection')


if __name__ == '__main__':
    unittest.main()
