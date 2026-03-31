import unittest
from types import SimpleNamespace

from main import determine_scan_types


def make_args(**overrides):
    defaults = {
        'xss_only': False,
        'xss_nuclei': False,
        'sql_only': False,
        'ssrf_only': False,
        'xxe_only': False,
        'nuclei_only': False,
        'nuclei': False,
        'nuclei_cves': False,
        'path_xss': False,
        'custom_param': False,
        'sqlmap': False,
        'param_discovery': False,
        'deep': False,
        'aggressive': False,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class DetermineScanTypesTests(unittest.TestCase):
    def test_xss_only_and_nuclei_full_can_be_combined(self):
        scan_types = determine_scan_types(make_args(xss_only=True, nuclei=True))
        self.assertIn('xss', scan_types)
        self.assertIn('nuclei-full', scan_types)

    def test_xss_only_and_standard_nuclei_can_be_combined(self):
        scan_types = determine_scan_types(make_args(xss_only=True, nuclei_only=True))
        self.assertIn('xss', scan_types)
        self.assertIn('nuclei', scan_types)

    def test_nuclei_modes_can_be_combined(self):
        scan_types = determine_scan_types(make_args(nuclei=True, nuclei_cves=True))
        self.assertIn('nuclei-full', scan_types)
        self.assertIn('nuclei-cves', scan_types)

    def test_default_includes_core_scans(self):
        scan_types = determine_scan_types(make_args())
        self.assertEqual(scan_types, ['xss', 'sqli', 'ssrf', 'nuclei'])

    def test_deep_and_aggressive_add_enhancements(self):
        scan_types = determine_scan_types(make_args(xss_only=True, deep=True, aggressive=True))
        self.assertIn('xss', scan_types)
        self.assertIn('path-xss', scan_types)
        self.assertIn('param-discovery', scan_types)
        self.assertIn('xxe', scan_types)


if __name__ == '__main__':
    unittest.main()
