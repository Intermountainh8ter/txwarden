"""Keep RPC credentials out of anything that is printed, logged or written to disk.

Hosted RPC providers put the API key in the URL (usually the path, sometimes the query string or
the user-info part). A URL therefore never belongs in a message, a result file or a cache file.
Two tools:

* ``redact_url`` reduces a URL to ``scheme://host[:port]`` (or ``rpc endpoint`` when it is not
  recognisably a URL), which is all that is ever shown.
* ``Redactor`` removes every piece of a *known* secret URL from arbitrary text, as a second line
  of defence for exception messages produced by libraries we do not control.
"""
from __future__ import annotations

from urllib.parse import unquote, urlsplit

PLACEHOLDER = "[redacted]"
GENERIC = "rpc endpoint"
_SCHEMES = ("http", "https", "ws", "wss")
_MIN_PIECE = 4  # shorter path segments ("v1", "rpc") are not secrets and would mangle messages


def redact_url(url: object) -> str:
    """``scheme://host[:port]`` of ``url``; the path, query, fragment and credentials are dropped.

    Anything that does not parse as an http(s)/ws(s) URL with a host yields ``"rpc endpoint"`` so
    a mistyped or malformed value (which may well be the key itself) is never echoed back.
    """
    try:
        parts = urlsplit(str(url).strip())
        scheme, host, port = parts.scheme.lower(), parts.hostname, parts.port
    except ValueError:
        return GENERIC
    if scheme not in _SCHEMES or not host:
        return GENERIC
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def _pieces(url: str) -> set[str]:
    """Every substring of ``url`` that could be a credential, in raw and percent-decoded form."""
    out: set[str] = set()
    raw = url.strip()
    if not raw:
        return out
    out.add(raw)
    try:
        parts = urlsplit(raw)
        netloc = parts.netloc
        userinfo = netloc.rpartition("@")[0] if "@" in netloc else ""
        tail = raw.split(netloc, 1)[1] if netloc and netloc in raw else ""
        candidates = [tail, parts.path, parts.query, parts.fragment, userinfo,
                      parts.password or "", parts.username or ""]
        candidates += parts.path.split("/")
        candidates += [kv.partition("=")[2] for kv in parts.query.split("&")]
        candidates += parts.query.split("&")
        if userinfo:
            out.add(netloc)  # "user:key@host" is a secret as a whole; the bare host is not
    except ValueError:
        candidates = [raw]
    for c in candidates:
        c = c.strip("/? #&")
        if len(c) >= _MIN_PIECE:
            out.add(c)
            out.add(unquote(c))
    return {p for p in out if p}


class Redactor:
    """Removes the pieces of the given secret URLs from text.

    >>> Redactor("https://node.example/v1/abcd1234abcd").scrub("GET /v1/abcd1234abcd failed")
    'GET /v1/[redacted] failed'
    """

    def __init__(self, *secrets: object):
        pieces: set[str] = set()
        for s in secrets:
            if s:
                pieces |= _pieces(str(s))
        # longest first, so a full URL is replaced as one unit rather than piecemeal
        self._pieces = sorted(pieces, key=len, reverse=True)

    def scrub(self, text: object) -> str:
        out = str(text)
        for piece in self._pieces:
            out = out.replace(piece, PLACEHOLDER)
        return out

    def exception(self, exc: BaseException) -> str:
        """``ExceptionType: message`` with the secrets removed; safe to print or store."""
        return self.scrub(f"{type(exc).__name__}: {exc}")
