"""Daily scan limits remain atomic and independent of analysis history."""
import unittest
from unittest.mock import Mock, patch

import app as application


class ScanAllowanceTests(unittest.TestCase):
    def test_public_sixth_scan_is_rejected(self):
        store = Mock()
        store.claim_scan_allowance.side_effect = [True] * 5 + [False]
        handler = Mock(return_value='scanned')
        with application.app.test_request_context(), patch.object(application, 'PUBLIC_MODE', True), patch.object(application, '_analysis_store', return_value=store):
            limited = application.scan_limited(handler)
            for _ in range(5):
                self.assertEqual(limited(), 'scanned')
            response, status = limited()
            self.assertEqual(status, 429)
            self.assertIn('5 scans', response.get_json()['error'])
            self.assertEqual(handler.call_count, 5)

    def test_local_has_no_quota(self):
        with application.app.test_request_context(), patch.object(application, 'PUBLIC_MODE', False), patch.object(application, '_analysis_store') as store:
            limited = application.scan_limited(lambda: 'scanned')
            for _ in range(20):
                self.assertEqual(limited(), 'scanned')
            store.assert_not_called()

    def test_quota_outage_blocks_public_scan(self):
        store = Mock()
        store.claim_scan_allowance.side_effect = RuntimeError('offline')
        with application.app.test_request_context(), patch.object(application, 'PUBLIC_MODE', True), patch.object(application, '_analysis_store', return_value=store):
            handler = Mock()
            _, status = application.scan_limited(handler)()
            self.assertEqual(status, 503)
            handler.assert_not_called()

