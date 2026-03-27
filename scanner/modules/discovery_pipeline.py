"""
Discovery pipeline for URL and parameter gathering with source metadata.
"""

from __future__ import annotations

import json
import re
import time
import concurrent.futures
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

from scanner.config import DISCOVERY_OUTPUT_DIR
from scanner.logger import logger
from scanner.modules.js_analyzer import JSAnalyzer
from scanner.playwright_spider import run_playwright_spider
from scanner.utils import check_tool_exists, get_domain_from_url, make_http_request, run_command


URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')
JS_PARAM_PATTERNS = [
    r'(?:param|parameter|query|get|post|data)\s*[:=]\s*["\']?([A-Za-z0-9_-]+)["\']?',
    r'\?([A-Za-z0-9_-]+)=',
    r'&([A-Za-z0-9_-]+)=',
    r'params\.([A-Za-z0-9_-]+)',
    r'req\.query\.([A-Za-z0-9_-]+)',
    r'new\s+URLSearchParams\([^)]*\)\.get\(["\']([A-Za-z0-9_-]+)["\']\)',
]
XML_URL_TAGS = {'loc', 'link', 'url', 'endpoint', 'href'}


@dataclass
class DiscoveryRecord:
    raw_url: str
    normalized_url: str
    source: str
    discovery_type: str
    host: str
    path: str
    query: str
    fragment: str
    param_names: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class DiscoveryPipeline:
    """Collect URLs and parameter names with metadata and persistence."""

    def __init__(
        self,
        target_url: str,
        timeout: Optional[int],
        verbose: bool = False,
        silent: bool = False,
        discovery_cache: Optional[str] = None,
        workers: int = 5,
    ):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.silent = silent
        self.discovery_cache = discovery_cache
        self.workers = max(1, workers)
        self.records: List[DiscoveryRecord] = []
        self.param_records: List[Dict] = []
        self.js_urls: List[str] = []
        self.output_dir: Optional[str] = None

    def run(self) -> Dict:
        if self.discovery_cache:
            self._load_cache(self.discovery_cache)
            return self._result_payload(loaded_from_cache=True)

        domain = get_domain_from_url(self.target_url)

        seed_record = self._build_record(self.target_url, source='target', discovery_type='seed_url')
        if seed_record:
            self.records.append(seed_record)

        self.records.extend(self._collect_playwright_records())
        self.records.extend(self._collect_gau_records(domain))
        self.records.extend(self._collect_wayback_records(domain))
        self.records.extend(self._collect_katana_records())

        self._expand_parameters_from_responses()
        self._analyze_linked_js()
        self._persist()

        return self._result_payload(loaded_from_cache=False)

    def _result_payload(self, loaded_from_cache: bool) -> Dict:
        source_counts: Dict[str, Dict[str, int]] = {}
        for record in self.records:
            bucket = source_counts.setdefault(record.source, {'urls': 0, 'params': 0})
            bucket['urls'] += 1
        for record in self.param_records:
            bucket = source_counts.setdefault(record['source'], {'urls': 0, 'params': 0})
            bucket['params'] += 1

        return {
            'records': [asdict(record) for record in self.records],
            'urls': [record.normalized_url for record in self.records],
            'parameters': [record['name'] for record in self.param_records],
            'parameter_records': list(self.param_records),
            'js_urls': list(self.js_urls),
            'output_dir': self.output_dir,
            'loaded_from_cache': loaded_from_cache,
            'source_counts': source_counts,
        }

    def _log(self, message: str) -> None:
        if not self.silent:
            logger.info(message)

    def _normalize_url(self, url: str) -> Optional[Dict]:
        if not url:
            return None

        candidate = url.strip()
        if not candidate:
            return None

        lowered = candidate.lower()
        if candidate.startswith('//'):
            candidate = f'https:{candidate}'
        elif not lowered.startswith(('http://', 'https://')):
            candidate = f'https://{candidate}'

        parsed = urlparse(candidate)
        if not parsed.netloc:
            return None

        scheme = parsed.scheme.lower() or 'https'
        host = parsed.hostname.lower() if parsed.hostname else parsed.netloc.lower()
        try:
            port = parsed.port
        except ValueError:
            return None
        if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
            host = f"{host}:{port}"

        path = parsed.path or '/'
        path = re.sub(r'/+', '/', path)

        normalized_url = urlunparse((
            scheme,
            host,
            path,
            parsed.params,
            parsed.query,
            '',
        ))

        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        return {
            'normalized_url': normalized_url,
            'host': host,
            'path': path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'param_names': params,
        }

    def _build_record(self, url: str, source: str, discovery_type: str, metadata: Optional[Dict] = None) -> Optional[DiscoveryRecord]:
        normalized = self._normalize_url(url)
        if not normalized:
            return None

        return DiscoveryRecord(
            raw_url=url,
            normalized_url=normalized['normalized_url'],
            source=source,
            discovery_type=discovery_type,
            host=normalized['host'],
            path=normalized['path'],
            query=normalized['query'],
            fragment=normalized['fragment'],
            param_names=normalized['param_names'],
            metadata=metadata or {},
        )

    def _record_param(self, name: str, source: str, discovery_type: str, url: Optional[str] = None, metadata: Optional[Dict] = None) -> None:
        if not name:
            return
        self.param_records.append({
            'name': name,
            'source': source,
            'discovery_type': discovery_type,
            'url': url,
            'metadata': metadata or {},
        })

    def _collect_playwright_records(self) -> List[DiscoveryRecord]:
        records: List[DiscoveryRecord] = []
        try:
            result = run_playwright_spider(
                self.target_url,
                timeout=self.timeout,
                max_pages=20,
                verbose=self.verbose,
                silent=self.silent,
            )
        except Exception as e:
            if self.verbose:
                logger.debug(f"Playwright discovery failed: {e}")
            return records

        for url in result.get('urls', []):
            record = self._build_record(url, source='playwright', discovery_type='live_crawl')
            if record:
                records.append(record)

        for param in result.get('parameters', []):
            self._record_param(param, source='playwright', discovery_type='dom_form')

        return records

    def _collect_gau_records(self, domain: str) -> List[DiscoveryRecord]:
        if not check_tool_exists('gau', 'gau --version'):
            return []

        success, output, _ = run_command(f"gau {domain}", timeout=self.timeout)
        if not success or not output:
            return []

        records: List[DiscoveryRecord] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            urls = URL_PATTERN.findall(line)
            if not urls and line.startswith(('http://', 'https://')):
                urls = [line]
            for url in urls:
                record = self._build_record(url, source='gau', discovery_type='historical_url')
                if record:
                    records.append(record)
        self._log(f"✅ [DISCOVERY] gau produced {len(records)} URL records")
        return records

    def _collect_wayback_records(self, domain: str) -> List[DiscoveryRecord]:
        if not check_tool_exists('waybackurls', 'waybackurls -h'):
            return []

        success, output, _ = run_command(f"echo '{domain}' | waybackurls", timeout=self.timeout)
        if not success or not output:
            return []

        records: List[DiscoveryRecord] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            urls = URL_PATTERN.findall(line)
            if not urls and line.startswith(('http://', 'https://')):
                urls = [line]
            for url in urls:
                record = self._build_record(url, source='waybackurls', discovery_type='historical_url')
                if record:
                    records.append(record)
        self._log(f"✅ [DISCOVERY] waybackurls produced {len(records)} URL records")
        return records

    def _collect_katana_records(self) -> List[DiscoveryRecord]:
        if not check_tool_exists('katana', 'katana -h'):
            return []

        cmd = f"katana -u {self.target_url} -d 3 -jc -fx -xhr -j -silent"
        success, output, _ = run_command(cmd, timeout=self.timeout)
        if not success or not output:
            return []

        records = self._parse_katana_output(output)
        self._log(f"✅ [DISCOVERY] katana produced {len(records)} URL records")
        return records

    def _parse_katana_output(self, output: str) -> List[DiscoveryRecord]:
        records: List[DiscoveryRecord] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith('{'):
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    data = None

                if isinstance(data, dict):
                    records.extend(self._parse_katana_jsonl_entry(data))
                    continue

            for url in URL_PATTERN.findall(line):
                record = self._build_record(url, source='katana', discovery_type='live_crawl', metadata={'raw_line': line})
                if record:
                    records.append(record)

        return records

    def _parse_katana_jsonl_entry(self, data: Dict) -> List[DiscoveryRecord]:
        records: List[DiscoveryRecord] = []

        candidate_urls = []
        for key in ['url', 'endpoint', 'request', 'response', 'xhr', 'source']:
            value = data.get(key)
            if isinstance(value, str):
                candidate_urls.extend(URL_PATTERN.findall(value))
            else:
                candidate_urls.extend(self._extract_urls_from_object(value))

        for url in candidate_urls:
            record = self._build_record(url, source='katana', discovery_type='live_crawl', metadata={'katana': data})
            if record:
                records.append(record)

        forms = data.get('forms') or data.get('form') or []
        if isinstance(forms, dict):
            forms = [forms]
        for form in forms:
            action = form.get('action') or data.get('url')
            if action:
                form_record = self._build_record(action, source='katana', discovery_type='form_action', metadata={'form': form})
                if form_record:
                    records.append(form_record)
            for field in form.get('inputs', []) + form.get('selects', []) + form.get('textareas', []):
                name = field.get('name') or field.get('id')
                self._record_param(name, source='katana', discovery_type='form_field', url=action, metadata={'field': field})

        return records

    def _extract_urls_from_object(self, value) -> List[str]:
        urls: List[str] = []
        if isinstance(value, str):
            urls.extend(URL_PATTERN.findall(value))
        elif isinstance(value, dict):
            for nested in value.values():
                urls.extend(self._extract_urls_from_object(nested))
        elif isinstance(value, list):
            for item in value:
                urls.extend(self._extract_urls_from_object(item))
        return urls

    def _expand_parameters_from_responses(self) -> None:
        base_records = list(self.records)

        for record in base_records:
            for param_name in record.param_names:
                self._record_param(param_name, source=record.source, discovery_type='query_param', url=record.normalized_url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self._fetch_and_extract_from_record, record): record
                for record in base_records
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    new_records, new_params, new_js_urls = future.result()
                    if new_records:
                        self.records.extend(new_records)
                    if new_params:
                        self.param_records.extend(new_params)
                    if new_js_urls:
                        self.js_urls.extend(new_js_urls)
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Response expansion error: {e}")

    def _fetch_and_extract_from_record(self, record: DiscoveryRecord):
        response, _, error = make_http_request(record.normalized_url, timeout=self.timeout, verify_ssl=False)
        if error or not response:
            return [], [], []
        return self._extract_from_html_content(record.normalized_url, response, record.source)

    def _extract_params_from_html(self, base_url: str, html_content: str, source: str) -> None:
        new_records, new_params, new_js_urls = self._extract_from_html_content(base_url, html_content, source)
        self.records.extend(new_records)
        self.param_records.extend(new_params)
        self.js_urls.extend(new_js_urls)

    def _extract_from_html_content(self, base_url: str, html_content: str, source: str):
        if self._looks_like_xml(html_content):
            self._log(f"🧾 [DISCOVERY] XML document detected at {base_url} - parsing as XML and recording for review")
            return self._extract_from_xml_content(base_url, html_content, source)

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
            soup = BeautifulSoup(html_content, 'lxml')
        new_records: List[DiscoveryRecord] = []
        new_params: List[Dict] = []
        new_js_urls: List[str] = []

        for form in soup.find_all('form'):
            action = form.get('action') or base_url
            action_url = urljoin(base_url, action)
            form_record = self._build_record(action_url, source=source, discovery_type='form_action')
            if form_record:
                new_records.append(form_record)

            for field in form.find_all(['input', 'textarea', 'select']):
                name = field.get('name') or field.get('id')
                if name:
                    new_params.append({
                        'name': name,
                        'source': source,
                        'discovery_type': 'form_field',
                        'url': action_url,
                        'metadata': {},
                    })

        for anchor in soup.find_all(['a', 'link']):
            href = anchor.get('href')
            if not href:
                continue
            anchor_url = urljoin(base_url, href)
            record = self._build_record(anchor_url, source=source, discovery_type='html_link')
            if record:
                new_records.append(record)

        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_url = urljoin(base_url, src)
                new_js_urls.append(js_url)
                js_record = self._build_record(js_url, source=source, discovery_type='script_src')
                if js_record:
                    new_records.append(js_record)
            else:
                script_text = script.get_text(" ", strip=False)
                for param in self._extract_params_from_js(script_text):
                    new_params.append({
                        'name': param,
                        'source': source,
                        'discovery_type': 'inline_script',
                        'url': base_url,
                        'metadata': {},
                    })
                for url in URL_PATTERN.findall(script_text):
                    script_record = self._build_record(urljoin(base_url, url), source=source, discovery_type='inline_script_url')
                    if script_record:
                        new_records.append(script_record)

        return new_records, new_params, new_js_urls

    def _looks_like_xml(self, content: str) -> bool:
        snippet = (content or '').lstrip()[:512].lower()
        if not snippet:
            return False
        if snippet.startswith('<?xml'):
            return True
        if any(tag in snippet for tag in ['<urlset', '<sitemapindex', '<rss', '<feed', '<svg', '<soap:', '<wsdl:']):
            return True
        if '<html' in snippet or '<!doctype html' in snippet:
            return False
        return bool(re.match(r'^<([a-z0-9_:.-]+)(\s|>)', snippet))

    def _extract_from_xml_content(self, base_url: str, xml_content: str, source: str):
        soup = BeautifulSoup(xml_content, 'xml')
        new_records: List[DiscoveryRecord] = []
        new_params: List[Dict] = []
        new_js_urls: List[str] = []

        xml_record = self._build_record(
            base_url,
            source=source,
            discovery_type='xml_document',
            metadata={'content_type': 'xml', 'review_note': 'XML response detected; inspect manually for XML-specific attack surface.'},
        )
        if xml_record:
            new_records.append(xml_record)

        for tag_name in XML_URL_TAGS:
            for tag in soup.find_all(tag_name):
                text = (tag.get_text() or '').strip()
                if not text:
                    continue
                for url in URL_PATTERN.findall(text):
                    record = self._build_record(urljoin(base_url, url), source=source, discovery_type='xml_link')
                    if record:
                        new_records.append(record)
                        for param_name in record.param_names:
                            new_params.append({
                                'name': param_name,
                                'source': source,
                                'discovery_type': 'xml_query_param',
                                'url': record.normalized_url,
                                'metadata': {},
                            })

        for url in self._extract_urls_from_object(soup.attrs):
            record = self._build_record(urljoin(base_url, url), source=source, discovery_type='xml_attribute_url')
            if record:
                new_records.append(record)

        return new_records, new_params, new_js_urls

    def _analyze_linked_js(self) -> None:
        unique_js_urls = list(dict.fromkeys(self.js_urls))
        if not unique_js_urls:
            return

        analyzer = JSAnalyzer()
        analyzer.analyze_js_files(unique_js_urls)

        for js_url, details in analyzer.get_file_results().items():
            for param in details.get('parameters', []):
                self._record_param(param, source='linked_js', discovery_type='js_param', url=js_url)

            for endpoint in details.get('endpoints', []):
                endpoint_url = urljoin(self.target_url, endpoint)
                record = self._build_record(endpoint_url, source='linked_js', discovery_type='js_endpoint', metadata={'js_url': js_url})
                if record:
                    self.records.append(record)

    def _extract_params_from_js(self, js_content: str) -> List[str]:
        params: List[str] = []
        for pattern in JS_PARAM_PATTERNS:
            for match in re.findall(pattern, js_content, re.IGNORECASE):
                if isinstance(match, tuple):
                    match = match[0]
                if match:
                    params.append(match)
        return params

    def _load_cache(self, cache_path: str) -> None:
        base_dir = Path(cache_path)
        urls_path = base_dir / 'urls.jsonl'
        params_path = base_dir / 'params.jsonl'

        self.records = []
        self.param_records = []
        self.js_urls = []

        if urls_path.exists():
            with open(urls_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    self.records.append(DiscoveryRecord(**data))
                    if data.get('discovery_type') == 'script_src':
                        self.js_urls.append(data.get('normalized_url'))

        if params_path.exists():
            with open(params_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    self.param_records.append(json.loads(line))

        self.output_dir = str(base_dir)
        self._log(f"✅ [DISCOVERY] Loaded {len(self.records)} URL records and {len(self.param_records)} parameter records from cache")

    def _persist(self) -> None:
        timestamp = int(time.time())
        target_key = re.sub(r'[^A-Za-z0-9._-]+', '_', get_domain_from_url(self.target_url) or 'target')
        base_dir = Path(DISCOVERY_OUTPUT_DIR) / f"{target_key}_{timestamp}"
        base_dir.mkdir(parents=True, exist_ok=True)

        urls_path = base_dir / 'urls.jsonl'
        params_path = base_dir / 'params.jsonl'
        summary_path = base_dir / 'summary.json'

        with open(urls_path, 'w') as f:
            for record in self.records:
                f.write(json.dumps(asdict(record)) + '\n')

        with open(params_path, 'w') as f:
            for record in self.param_records:
                f.write(json.dumps(record) + '\n')

        with open(summary_path, 'w') as f:
            json.dump({
                'target': self.target_url,
                'total_url_records': len(self.records),
                'total_param_records': len(self.param_records),
                'total_js_urls': len(self.js_urls),
            }, f, indent=2)

        self.output_dir = str(base_dir)
