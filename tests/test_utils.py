import unittest
from unittest.mock import Mock, patch

import requests

from scanner.utils import make_http_request


class HttpRequestPolicyTests(unittest.TestCase):
    @patch('scanner.utils.time.sleep', return_value=None)
    @patch('scanner.utils.requests.get')
    def test_make_http_request_retries_timeouts_and_returns_error(self, mock_get, _mock_sleep):
        mock_get.side_effect = requests.Timeout()

        body, status, error = make_http_request('https://example.com', timeout=0)

        self.assertIsNone(body)
        self.assertIsNone(status)
        self.assertIn('Request timeout after 60s', error)
        self.assertEqual(mock_get.call_count, 3)

    @patch('scanner.utils.requests.get')
    def test_make_http_request_uses_default_http_timeout_when_unset(self, mock_get):
        response = Mock()
        response.text = 'ok'
        response.status_code = 200
        mock_get.return_value = response

        body, status, error = make_http_request('https://example.com', timeout=0)

        self.assertEqual(body, 'ok')
        self.assertEqual(status, 200)
        self.assertIsNone(error)
        self.assertEqual(mock_get.call_args.kwargs['timeout'], 60)


if __name__ == '__main__':
    unittest.main()
