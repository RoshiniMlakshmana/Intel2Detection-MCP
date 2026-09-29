"""Shared TLS settings for outbound public-source fetches (feeds, articles, frameworks, APIs).

SIEM and SMTP connections keep their own explicitly configured contexts.
"""

import ssl

try:
    import certifi
except ImportError:  # pragma: no cover - certifi is a declared dependency
    certifi = None


def tls_context(max_tls12=False):
    """System trust store plus Mozilla's CA bundle.

    On Windows, Python only sees roots already installed in the local ROOT
    store; Windows fetches many roots on demand for browsers, so a valid chain
    (observed: Malpedia via HARICA TLS RSA Root CA 2021) fails in Python with
    "self-signed certificate in certificate chain". Adding certifi's bundle is
    additive: verification and hostname checks stay on.

    max_tls12 is a narrow per-publisher compatibility setting for a feed whose
    CDN refuses Python's TLS 1.3 handshake but serves the same public feed
    over TLS 1.2 (observed: CISA advisories RSS). It never disables
    verification.
    """
    context = ssl.create_default_context()
    if certifi is not None:
        context.load_verify_locations(certifi.where())
    if max_tls12:
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    return context
