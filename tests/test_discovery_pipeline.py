import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scanner.modules.discovery_pipeline as discovery_pipeline
from scanner.modules.discovery_pipeline import DiscoveryPipeline


class DiscoveryPipelineTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = DiscoveryPipeline('https://example.com', timeout=5, silent=True)

    def test_normalize_url_preserves_query_and_strips_default_port(self):
        normalized = self.pipeline._normalize_url('HTTPS://Example.com:443/path//to/page?q=1&x=2#frag')
        self.assertEqual(normalized['normalized_url'], 'https://example.com/path/to/page?q=1&x=2')
        self.assertEqual(normalized['fragment'], 'frag')
        self.assertEqual(normalized['param_names'], ['q', 'x'])

    def test_parse_katana_jsonl_extracts_urls_and_form_params(self):
        line = json.dumps({
            'url': 'https://example.com/search?q=test',
            'forms': [{
                'action': 'https://example.com/form',
                'inputs': [{'name': 'message'}, {'id': 'nickname'}],
                'selects': [],
                'textareas': [{'name': 'comment'}],
            }],
            'xhr': [{'request': {'endpoint': 'https://example.com/api/list?tag=1'}}],
        })

        records = self.pipeline._parse_katana_output(line)
        urls = [record.normalized_url for record in records]
        self.assertIn('https://example.com/search?q=test', urls)
        self.assertIn('https://example.com/form', urls)
        self.assertIn('https://example.com/api/list?tag=1', urls)

        param_names = [record['name'] for record in self.pipeline.param_records]
        self.assertIn('message', param_names)
        self.assertIn('nickname', param_names)
        self.assertIn('comment', param_names)

    @patch('scanner.modules.discovery_pipeline.make_http_request')
    def test_expand_parameters_from_html_collects_forms_links_and_inline_script(self, mock_request):
        mock_request.return_value = (
            '''
            <html>
              <body>
                <form action="/submit">
                  <input name="search">
                  <textarea id="details"></textarea>
                </form>
                <a href="/items?id=5">Item</a>
                <script>
                  var x = "?token=1";
                  fetch("https://example.com/api?q=superman");
                </script>
              </body>
            </html>
            ''',
            200,
            None,
        )
        self.pipeline.records = [
            self.pipeline._build_record('https://example.com/start?q=1', source='gau', discovery_type='historical_url')
        ]

        self.pipeline._expand_parameters_from_responses()

        urls = [record.normalized_url for record in self.pipeline.records]
        self.assertIn('https://example.com/submit', urls)
        self.assertIn('https://example.com/items?id=5', urls)
        self.assertIn('https://example.com/api?q=superman', urls)

        param_names = [record['name'] for record in self.pipeline.param_records]
        self.assertIn('q', param_names)
        self.assertIn('search', param_names)
        self.assertIn('details', param_names)
        self.assertIn('token', param_names)

    def test_persist_writes_discovery_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = discovery_pipeline.DISCOVERY_OUTPUT_DIR
            discovery_pipeline.DISCOVERY_OUTPUT_DIR = Path(temp_dir)
            try:
                self.pipeline.records = [
                    self.pipeline._build_record('https://example.com/path?q=1', source='gau', discovery_type='historical_url')
                ]
                self.pipeline.param_records = [{'name': 'q', 'source': 'gau', 'discovery_type': 'query_param', 'url': 'https://example.com/path?q=1', 'metadata': {}}]
                self.pipeline._persist()

                output_dirs = list(Path(temp_dir).iterdir())
                self.assertEqual(len(output_dirs), 1)
                output_dir = output_dirs[0]
                self.assertTrue((output_dir / 'urls.jsonl').exists())
                self.assertTrue((output_dir / 'params.jsonl').exists())
                self.assertTrue((output_dir / 'summary.json').exists())
            finally:
                discovery_pipeline.DISCOVERY_OUTPUT_DIR = original_dir

    @patch('scanner.modules.discovery_pipeline.JSAnalyzer')
    def test_analyze_linked_js_extracts_params_and_endpoints(self, mock_analyzer_cls):
        analyzer = mock_analyzer_cls.return_value
        analyzer.get_file_results.return_value = {
            'https://example.com/static/app.js': {
                'parameters': ['token', 'lang'],
                'endpoints': ['/api/search?q=1', 'https://example.com/api/items?id=2'],
                'sinks': [],
            }
        }

        self.pipeline.js_urls = ['https://example.com/static/app.js']
        self.pipeline._analyze_linked_js()

        params = [record['name'] for record in self.pipeline.param_records]
        urls = [record.normalized_url for record in self.pipeline.records]
        self.assertIn('token', params)
        self.assertIn('lang', params)
        self.assertIn('https://example.com/api/search?q=1', urls)
        self.assertIn('https://example.com/api/items?id=2', urls)

    def test_load_cache_reuses_saved_discovery_records(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            urls_path = base / 'urls.jsonl'
            params_path = base / 'params.jsonl'

            with open(urls_path, 'w') as f:
                f.write(json.dumps({
                    'raw_url': 'https://example.com/path?q=1',
                    'normalized_url': 'https://example.com/path?q=1',
                    'source': 'gau',
                    'discovery_type': 'historical_url',
                    'host': 'example.com',
                    'path': '/path',
                    'query': 'q=1',
                    'fragment': '',
                    'param_names': ['q'],
                    'metadata': {},
                }) + '\n')

            with open(params_path, 'w') as f:
                f.write(json.dumps({
                    'name': 'q',
                    'source': 'gau',
                    'discovery_type': 'query_param',
                    'url': 'https://example.com/path?q=1',
                    'metadata': {},
                }) + '\n')

            pipeline = DiscoveryPipeline('https://example.com', timeout=5, silent=True, discovery_cache=temp_dir)
            result = pipeline.run()

            self.assertTrue(result['loaded_from_cache'])
            self.assertEqual(result['output_dir'], temp_dir)
            self.assertEqual(result['urls'], ['https://example.com/path?q=1'])
            self.assertEqual(result['parameters'], ['q'])

    def test_extract_from_xml_content_collects_sitemap_urls_and_params(self):
        records, params, js_urls = self.pipeline._extract_from_html_content(
            'https://example.com/sitemap.xml',
            '''<?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <url><loc>https://example.com/products?id=7</loc></url>
              <url><loc>https://example.com/search?q=superman</loc></url>
            </urlset>''',
            'gau',
        )

        urls = [record.normalized_url for record in records]
        param_names = [record['name'] for record in params]

        self.assertIn('https://example.com/sitemap.xml', urls)
        self.assertIn('https://example.com/products?id=7', urls)
        self.assertIn('https://example.com/search?q=superman', urls)
        self.assertIn('id', param_names)
        self.assertIn('q', param_names)
        self.assertEqual(js_urls, [])

    @patch('scanner.modules.discovery_pipeline.make_http_request')
    @patch.object(DiscoveryPipeline, '_collect_katana_records', return_value=[])
    @patch.object(DiscoveryPipeline, '_collect_wayback_records', return_value=[])
    @patch.object(DiscoveryPipeline, '_collect_gau_records', return_value=[])
    @patch.object(DiscoveryPipeline, '_collect_playwright_records', return_value=[])
    def test_run_seeds_target_url_when_tool_discovery_is_empty(
        self,
        _mock_playwright,
        _mock_gau,
        _mock_wayback,
        _mock_katana,
        mock_request,
    ):
        mock_request.return_value = (
            '''
            <html>
              <body>
                <a href="/about">About</a>
                <form action="/search">
                  <input name="q">
                </form>
              </body>
            </html>
            ''',
            200,
            None,
        )

        result = self.pipeline.run()

        self.assertIn('https://example.com/', result['urls'])
        self.assertIn('https://example.com/about', result['urls'])
        self.assertIn('https://example.com/search', result['urls'])
        self.assertIn('q', result['parameters'])
        self.assertEqual(result['source_counts']['target']['urls'], 3)

    @patch('scanner.modules.discovery_pipeline.run_command')
    @patch('scanner.modules.discovery_pipeline.check_tool_exists', return_value=True)
    def test_collect_gau_records_ignores_warning_lines_and_keeps_urls(self, _mock_tool_exists, mock_run_command):
        mock_run_command.return_value = (
            True,
            (
                'time="2026-03-26T20:52:37+05:45" level=warning msg="error reading config"\n'
                'https://www.rijksoverheid.nl/sitemap\n'
                'https://www.rijksoverheid.nl/toegankelijkheid\n'
            ),
            '',
        )

        records = self.pipeline._collect_gau_records('rijksoverheid.nl')
        urls = [record.normalized_url for record in records]

        self.assertEqual(len(records), 2)
        self.assertIn('https://www.rijksoverheid.nl/sitemap', urls)
        self.assertIn('https://www.rijksoverheid.nl/toegankelijkheid', urls)


if __name__ == '__main__':
    unittest.main()
