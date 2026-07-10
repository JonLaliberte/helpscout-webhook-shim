"""Help Scout -> Hermes webhook signing shim.

Help Scout signs webhooks with base64(HMAC-SHA1(raw_body)) in the
X-HelpScout-Signature header. Hermes's generic webhook adapter only speaks
HMAC-SHA256 (hex) in X-Webhook-Signature. The two never validate against each
other, so this shim sits in between:

    1. Verify Help Scout's SHA1/base64 signature over the RAW request body
       (this is the real authentication -- Help Scout is an unattended machine
       and cannot do interactive auth).
    2. Re-sign the SAME raw bytes as HMAC-SHA256 (hex) with Hermes's global
       webhook secret.
    3. Forward the untouched body to Hermes's webhook route.

Signing must happen over the exact bytes received -- never a re-serialized
copy -- or the HMAC will not match. We therefore read request.get_data() once
and pass it straight through.
"""

import base64
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.request

from flask import Flask, request, Response

HS_SECRET = os.environ["HS_WEBHOOK_SECRET"].encode()
HERMES_SECRET = os.environ["WEBHOOK_SECRET"].encode()
HERMES_URL = os.environ.get(
    "HERMES_WEBHOOK_URL",
    "http://127.0.0.1:8644/webhooks/helpscout-tickets",
)
FORWARD_TIMEOUT = float(os.environ.get("FORWARD_TIMEOUT", "15"))

app = Flask(__name__)


def _log(msg):
    print(f"[hs-shim] {msg}", file=sys.stderr, flush=True)


@app.post("/hs")
def relay():
    raw = request.get_data()  # RAW bytes -- verify and re-sign over these exactly.

    expected = base64.b64encode(
        hmac.new(HS_SECRET, raw, hashlib.sha1).digest()
    ).decode()
    provided = request.headers.get("X-HelpScout-Signature", "")
    if not hmac.compare_digest(provided, expected):
        _log("rejected: bad Help Scout signature")
        return Response("bad HS signature", status=401)

    event = request.headers.get("X-HelpScout-Event", "unknown")
    sig256 = hmac.new(HERMES_SECRET, raw, hashlib.sha256).hexdigest()
    fwd = urllib.request.Request(
        HERMES_URL,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Signature": sig256,
            "X-HelpScout-Event": event,
        },
    )

    try:
        with urllib.request.urlopen(fwd, timeout=FORWARD_TIMEOUT) as r:
            _log(f"forwarded event={event} -> Hermes {r.status}")
            return Response(r.read(), status=r.status)
    except urllib.error.HTTPError as e:
        body = e.read()
        _log(f"Hermes rejected event={event}: {e.code}")
        return Response(body, status=e.code)
    except urllib.error.URLError as e:
        _log(f"cannot reach Hermes at {HERMES_URL}: {e.reason}")
        return Response("upstream unreachable", status=502)


@app.get("/healthz")
def health():
    return "ok"
