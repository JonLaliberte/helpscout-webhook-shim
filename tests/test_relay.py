"""relay.py: Help Scout verification and the Hermes HMAC V2 re-signing.

Run: python -m unittest discover -s tests   (needs flask, as in the image)
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from unittest import mock

os.environ.setdefault("HS_WEBHOOK_SECRET", "hs-secret")
os.environ.setdefault("WEBHOOK_SECRET", "hermes-secret")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import relay  # noqa: E402


def hs_sig(body):
    return base64.b64encode(hmac.new(b"hs-secret", body, hashlib.sha1).digest()).decode()


class FakeResponse:
    status = 200

    def read(self):
        return b'{"status":"ok"}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class SignV2(unittest.TestCase):
    def test_signature_is_hmac_of_timestamp_dot_body(self):
        ts, sig = relay.sign_v2(b'{"a":1}', now=1795486545.9)
        self.assertEqual(ts, "1795486545")
        want = hmac.new(b"hermes-secret", b'1795486545.{"a":1}', hashlib.sha256).hexdigest()
        self.assertEqual(sig, want)

    def test_timestamp_is_now(self):
        ts, _ = relay.sign_v2(b"x")
        self.assertLessEqual(abs(int(ts) - time.time()), 2)


class Relay(unittest.TestCase):
    def setUp(self):
        self.client = relay.app.test_client()

    def post(self, body, sig=None, event="convo.created"):
        return self.client.post("/hs", data=body, headers={
            "X-HelpScout-Signature": hs_sig(body) if sig is None else sig,
            "X-HelpScout-Event": event, "Content-Type": "application/json"})

    def test_forwards_v2_headers_only(self):
        sent = {}

        def fake_urlopen(req, timeout):
            sent["req"] = req
            return FakeResponse()

        with mock.patch.object(relay.urllib.request, "urlopen", fake_urlopen):
            r = self.post(b'{"id":99999}')
        self.assertEqual(r.status_code, 200)
        req = sent["req"]
        headers = {k.lower(): v for k, v in req.header_items()}
        self.assertNotIn("x-webhook-signature", headers)
        ts, sig = headers["x-webhook-timestamp"], headers["x-webhook-signature-v2"]
        want = hmac.new(b"hermes-secret", ts.encode() + b"." + req.data, hashlib.sha256).hexdigest()
        self.assertEqual(sig, want)
        self.assertEqual(json.loads(req.data)["event_type"], "convo.created")
        self.assertEqual(headers["x-helpscout-event"], "convo.created")

    def test_bad_help_scout_signature_is_refused_without_forwarding(self):
        with mock.patch.object(relay.urllib.request, "urlopen") as urlopen:
            r = self.post(b'{"id":1}', sig="nope")
        self.assertEqual(r.status_code, 401)
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
