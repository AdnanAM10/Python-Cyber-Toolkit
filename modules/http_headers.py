"""
modules/http_headers.py
=======================

HTTP security-header auditor for educational use.

The tool performs one HTTP GET request and inspects response headers.

It does NOT:
- crawl links
- follow redirects
- brute-force paths
- fuzz endpoints
- send attack payloads
- attempt exploitation

AUTHORIZATION
-------------
Local loopback targets are allowed without an authorization flag.

Non-local targets require authorized=True and should only be checked
when the user owns the system or has explicit permission to test it.

A missing header is a configuration observation, not proof that a
website is vulnerable.

Standard library only.
"""

import ipaddress
import urllib.error
import urllib.parse
import urllib.request


USER_AGENT = (
    "CyberToolkit-Edu/1.0 "
    "(educational security-header checker)"
)

DEFAULT_TIMEOUT: float = 10.0

ALLOWED_SCHEMES: frozenset[str] = frozenset(
    {
        "http",
        "https",
    }
)


SECURITY_HEADERS: dict[str, dict[str, str | bool]] = {
    "Content-Security-Policy": {
        "recommendation": (
            "Consider reviewing whether a Content-Security-Policy "
            "header is appropriate for this application."
        ),
    },

    "Strict-Transport-Security": {
        "recommendation": (
            "For HTTPS deployments, consider reviewing whether "
            "Strict-Transport-Security should be enabled."
        ),
        "https_only": True,
    },

    "X-Content-Type-Options": {
        "recommendation": (
            "Consider reviewing whether "
            "X-Content-Type-Options: nosniff should be enabled."
        ),
    },

    "X-Frame-Options": {
        "recommendation": (
            "Consider reviewing framing protections such as "
            "X-Frame-Options or an appropriate CSP frame-ancestors policy."
        ),
    },

    "Referrer-Policy": {
        "recommendation": (
            "Consider reviewing whether a Referrer-Policy "
            "should be configured."
        ),
    },

    "Permissions-Policy": {
        "recommendation": (
            "Consider reviewing whether Permissions-Policy "
            "should restrict unnecessary browser features."
        ),
    },
}


class _NoRedirectHandler(
    urllib.request.HTTPRedirectHandler
):
    """
    Prevent urllib from automatically following redirects.

    This keeps the auditor limited to one exact requested URL.
    """

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def _parse_url(
    url: str,
) -> urllib.parse.ParseResult:
    """
    Parse and validate a basic HTTP/HTTPS URL.
    """

    try:
        parsed = urllib.parse.urlparse(
            url
        )
    except ValueError as exc:
        raise ValueError(
            f"Could not parse a valid URL: {exc}"
        ) from exc

    if (
        parsed.scheme
        and parsed.scheme.lower()
        not in ALLOWED_SCHEMES
    ):
        raise ValueError(
            f"Scheme {parsed.scheme!r} is not allowed. "
            "Only 'http' and 'https' are supported."
        )

    if (
        not parsed.scheme
        or not parsed.netloc
        or parsed.hostname is None
    ):
        raise ValueError(
            "Could not parse a valid URL. "
            "Include the scheme, for example "
            "'https://example.com/'."
        )

    # Accessing .port validates malformed ports such as :abc or :99999.
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(
            f"Invalid URL port: {exc}"
        ) from exc

    return parsed


def _is_local_target(
    parsed: urllib.parse.ParseResult,
) -> bool:
    """
    Return True when the URL host is localhost or a loopback IP.
    """

    hostname = parsed.hostname

    if hostname is None:
        return False

    hostname = hostname.lower()

    if hostname == "localhost":
        return True

    try:
        address = ipaddress.ip_address(
            hostname
        )
    except ValueError:
        return False

    return address.is_loopback


def _build_request(
    url: str,
) -> urllib.request.Request:
    """
    Build the single GET request used by the auditor.
    """

    request = urllib.request.Request(
        url,
        method="GET",
    )

    request.add_header(
        "User-Agent",
        USER_AGENT,
    )

    request.add_header(
        "Accept",
        "*/*",
    )

    return request


def _open_request(
    request: urllib.request.Request,
    timeout: float,
):
    """
    Open exactly one URL without automatically following redirects.
    """

    opener = urllib.request.build_opener(
        _NoRedirectHandler()
    )

    return opener.open(
        request,
        timeout=timeout,
    )


def _read_status_and_headers(
    response,
) -> tuple[int | None, dict[str, str]]:
    """
    Extract status and response headers.
    """

    status = getattr(
        response,
        "status",
        None,
    )

    if status is None:
        status = getattr(
            response,
            "code",
            None,
        )

    headers: dict[str, str] = {}

    raw_headers = getattr(
        response,
        "headers",
        None,
    )

    if raw_headers is not None:
        for name, value in raw_headers.items():
            headers[str(name)] = str(
                value
            )

    return status, headers


def _classify(
    headers: dict[str, str],
    scheme: str,
) -> tuple[
    list[str],
    list[str],
    list[str],
]:
    """
    Classify checked security headers.

    Header-name matching is case-insensitive.
    """

    lower_headers = {
        name.lower(): value
        for name, value in headers.items()
    }

    present: list[str] = []
    missing: list[str] = []
    recommendations: list[str] = []

    for canonical_name, info in SECURITY_HEADERS.items():

        lower_name = canonical_name.lower()

        if lower_name in lower_headers:
            present.append(
                canonical_name
            )

            if (
                canonical_name
                == "Strict-Transport-Security"
                and scheme.lower() == "http"
            ):
                recommendations.append(
                    "Strict-Transport-Security was observed on an "
                    "HTTP response, but HSTS is relevant when delivered "
                    "over HTTPS."
                )

            continue

        https_only = bool(
            info.get(
                "https_only",
                False,
            )
        )

        if (
            https_only
            and scheme.lower() == "http"
        ):
            recommendations.append(
                "Strict-Transport-Security was not evaluated as missing "
                "because HSTS is relevant to HTTPS responses."
            )
            continue

        missing.append(
            canonical_name
        )

        recommendations.append(
            str(
                info["recommendation"]
            )
        )

    return (
        present,
        missing,
        recommendations,
    )


def _build_result(
    url: str,
    status_code: int | None,
    headers: dict[str, str],
    scheme: str,
) -> dict:
    """
    Build a successful audit result.
    """

    (
        present,
        missing,
        recommendations,
    ) = _classify(
        headers,
        scheme,
    )

    if missing:
        recommendations.insert(
            0,
            (
                "Note: missing headers are configuration observations, "
                "not proof of a vulnerability."
            ),
        )
    else:
        recommendations.insert(
            0,
            (
                "All applicable checked headers were present. "
                "Their values should still be reviewed for suitability."
            ),
        )

    return {
        "url": url,
        "status_code": status_code,
        "headers": headers,
        "present_security_headers": present,
        "missing_security_headers": missing,
        "recommendations": recommendations,
        "success": True,
        "error": None,
    }


def _failure_result(
    url: str,
    error: str,
) -> dict:
    """
    Build a standard network/request failure result.
    """

    return {
        "url": url,
        "status_code": None,
        "headers": {},
        "present_security_headers": [],
        "missing_security_headers": [],
        "recommendations": [],
        "success": False,
        "error": error,
    }


def audit_http_headers(
    url: str,
    authorized: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """
    Audit common HTTP response security headers.

    A successful audit means that an HTTP response was received and
    its headers were inspected. It does NOT mean the site is secure.
    """

    if not isinstance(
        url,
        str,
    ):
        raise TypeError(
            f"audit_http_headers() expects a str for 'url', "
            f"got {type(url).__name__}."
        )

    url = url.strip()

    if not url:
        raise ValueError(
            "Could not parse a valid URL."
        )

    parsed = _parse_url(
        url
    )

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Scheme {parsed.scheme!r} is not allowed. "
            "Only 'http' and 'https' are supported."
        )

    # Authorization must be checked before any network request.
    if (
        not _is_local_target(parsed)
        and authorized is not True
    ):
        raise PermissionError(
            "Refusing to audit a non-local target. "
            "Only audit systems you own or have explicit permission "
            "to test. Pass authorized=True only when that is true."
        )

    if (
        isinstance(timeout, bool)
        or not isinstance(
            timeout,
            (int, float),
        )
    ):
        raise TypeError(
            "audit_http_headers() expects a number for 'timeout'."
        )

    timeout = float(
        timeout
    )

    if timeout <= 0:
        raise ValueError(
            "'timeout' must be positive."
        )

    request = _build_request(
        url
    )

    try:
        response = _open_request(
            request,
            timeout,
        )

    except urllib.error.HTTPError as exc:
        # HTTP errors such as 404 and 500 are still genuine HTTP
        # responses with headers. Audit those headers normally.
        try:
            status_code, headers = (
                _read_status_and_headers(
                    exc
                )
            )

            return _build_result(
                url,
                status_code,
                headers,
                scheme,
            )

        finally:
            try:
                exc.close()
            except Exception:
                pass

    except urllib.error.URLError as exc:
        return _failure_result(
            url,
            f"Network error: {exc.reason}",
        )

    except OSError as exc:
        return _failure_result(
            url,
            f"Request failed: {exc}",
        )

    try:
        status_code, headers = (
            _read_status_and_headers(
                response
            )
        )

        return _build_result(
            url,
            status_code,
            headers,
            scheme,
        )

    finally:
        close_method = getattr(
            response,
            "close",
            None,
        )

        if callable(
            close_method
        ):
            close_method()


if __name__ == "__main__":

    demo_url = (
        "http://127.0.0.1:8000/"
    )

    print(
        "=" * 60
    )

    print(
        "HTTP Security-Header Auditor Demo"
    )

    print(
        "=" * 60
    )

    print(
        f"Target: {demo_url}"
    )

    print()

    print(
        "This demo checks your own loopback interface."
    )

    print(
        "For a successful demo, start this in another terminal:"
    )

    print()

    print(
        "    python -m http.server 8000"
    )

    print()

    result = audit_http_headers(
        demo_url,
        authorized=False,
        timeout=5.0,
    )

    if result["success"]:

        print(
            f"Status: {result['status_code']}"
        )

        print(
            f"Headers received: {len(result['headers'])}"
        )

        print()

        print(
            "Security headers present:"
        )

        if result["present_security_headers"]:
            for header in result[
                "present_security_headers"
            ]:
                print(
                    f"  - {header}"
                )
        else:
            print(
                "  (none of the checked headers)"
            )

        print()

        print(
            "Missing applicable security headers:"
        )

        if result["missing_security_headers"]:
            for header in result[
                "missing_security_headers"
            ]:
                print(
                    f"  - {header}"
                )
        else:
            print(
                "  (none)"
            )

        print()

        print(
            "Observations:"
        )

        for recommendation in result[
            "recommendations"
        ]:
            print(
                f"  - {recommendation}"
            )

    else:

        print(
            f"Request failed: {result['error']}"
        )

        print()

        print(
            "If you expected the demo to succeed, start:"
        )

        print(
            "    python -m http.server 8000"
        )

        print(
            "in a separate PowerShell window."
        )

    print()

    print(
        "=" * 60
    )

    print(
        "Missing headers are configuration observations, "
        "not proof of a vulnerability."
    )

    print(
        "=" * 60
    )

