"""
Tests for modules/http_headers.py.

All HTTP/network operations are mocked.
No external website is contacted.
"""

import http.client
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from modules.http_headers import (
    SECURITY_HEADERS,
    USER_AGENT,
    _NoRedirectHandler,
    _classify,
    _is_local_target,
    _parse_url,
    audit_http_headers,
)


def make_response(
    status: int,
    headers: dict[str, str],
) -> MagicMock:
    """
    Build a mocked urllib response.
    """

    response = MagicMock()

    response.status = status
    response.code = status

    message = (
        http.client.HTTPMessage()
    )

    for name, value in headers.items():
        message[name] = value

    response.headers = message

    return response


def make_http_error(
    status: int,
    headers: dict[str, str],
) -> urllib.error.HTTPError:
    """
    Build a real HTTPError with headers.
    """

    message = (
        http.client.HTTPMessage()
    )

    for name, value in headers.items():
        message[name] = value

    return urllib.error.HTTPError(
        url="http://localhost/",
        code=status,
        msg="HTTP error",
        hdrs=message,
        fp=None,
    )


def test_nonlocal_requires_authorization():

    with patch(
        "modules.http_headers._open_request"
    ) as open_mock:

        with pytest.raises(
            PermissionError,
            match="authorized=True",
        ):
            audit_http_headers(
                "http://example.com/"
            )

        open_mock.assert_not_called()


@pytest.mark.parametrize(
    "authorization",
    [
        False,
        None,
        1,
        "True",
    ],
)
def test_nonlocal_rejects_invalid_authorization(
    authorization,
):

    with patch(
        "modules.http_headers._open_request"
    ) as open_mock:

        with pytest.raises(
            PermissionError
        ):
            audit_http_headers(
                "http://example.com/",
                authorized=authorization,
            )

        open_mock.assert_not_called()


def test_nonlocal_allowed_with_true():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "http://example.com/",
            authorized=True,
        )

    assert result["success"] is True


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.0.0.2/",
        "http://[::1]/",
    ],
)
def test_loopback_allowed_without_authorization(
    url,
):

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            url
        )

    assert result["success"] is True


def test_local_target_helper():

    assert _is_local_target(
        _parse_url(
            "http://localhost/"
        )
    )

    assert _is_local_target(
        _parse_url(
            "http://127.0.0.1/"
        )
    )

    assert _is_local_target(
        _parse_url(
            "http://127.0.0.25/"
        )
    )

    assert _is_local_target(
        _parse_url(
            "http://[::1]/"
        )
    )

    assert not _is_local_target(
        _parse_url(
            "http://example.com/"
        )
    )


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "ssh://example.com/",
        "file:///tmp/example",
    ],
)
def test_invalid_scheme_rejected(
    url,
):

    with pytest.raises(
        ValueError,
        match="not allowed",
    ):
        audit_http_headers(
            url,
            authorized=True,
        )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "example.com",
        "http:///missing-host",
    ],
)
def test_malformed_urls_rejected(
    url,
):

    with pytest.raises(
        ValueError,
        match="valid URL",
    ):
        audit_http_headers(
            url,
            authorized=True,
        )


def test_invalid_port_rejected():

    with pytest.raises(
        ValueError,
        match="Invalid URL port",
    ):
        audit_http_headers(
            "http://localhost:notaport/"
        )


def test_out_of_range_port_rejected():

    with pytest.raises(
        ValueError,
        match="Invalid URL port",
    ):
        audit_http_headers(
            "http://localhost:99999/"
        )


def test_non_string_url_rejected():

    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        audit_http_headers(
            12345
        )


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        -0.1,
    ],
)
def test_non_positive_timeout_rejected(
    timeout,
):

    with pytest.raises(
        ValueError,
        match="positive",
    ):
        audit_http_headers(
            "http://localhost/",
            timeout=timeout,
        )


@pytest.mark.parametrize(
    "timeout",
    [
        "fast",
        True,
        None,
    ],
)
def test_invalid_timeout_type_rejected(
    timeout,
):

    with pytest.raises(
        TypeError,
        match="expects a number",
    ):
        audit_http_headers(
            "http://localhost/",
            timeout=timeout,
        )


def test_successful_response():

    response = make_response(
        200,
        {
            "Content-Security-Policy":
                "default-src 'self'",
            "X-Frame-Options":
                "DENY",
        },
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert result["success"] is True
    assert result["error"] is None
    assert result["status_code"] == 200

    assert (
        "Content-Security-Policy"
        in result["present_security_headers"]
    )

    assert (
        "X-Frame-Options"
        in result["present_security_headers"]
    )


def test_request_uses_get_and_user_agent():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ) as open_mock:

        audit_http_headers(
            "http://localhost/"
        )

    request = (
        open_mock.call_args.args[0]
    )

    assert (
        request.get_method()
        == "GET"
    )

    assert (
        "CyberToolkit-Edu"
        in request.get_header(
            "User-agent"
        )
    )


def test_configured_user_agent_is_descriptive():

    assert (
        "educational"
        in USER_AGENT.lower()
    )


def test_case_insensitive_header_matching():

    response = make_response(
        200,
        {
            "content-security-policy":
                "default-src 'self'",
            "X-FRAME-OPTIONS":
                "DENY",
            "referrer-policy":
                "no-referrer",
        },
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert (
        "Content-Security-Policy"
        in result["present_security_headers"]
    )

    assert (
        "X-Frame-Options"
        in result["present_security_headers"]
    )

    assert (
        "Referrer-Policy"
        in result["present_security_headers"]
    )


def test_classify_case_insensitive():

    present, missing, _ = _classify(
        {
            "X-CONTENT-TYPE-OPTIONS":
                "nosniff",
        },
        "https",
    )

    assert (
        "X-Content-Type-Options"
        in present
    )

    assert (
        "X-Content-Type-Options"
        not in missing
    )


def test_http_excludes_hsts_from_missing():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert (
        "Strict-Transport-Security"
        not in result[
            "missing_security_headers"
        ]
    )

    assert len(
        result[
            "missing_security_headers"
        ]
    ) == 5

    assert any(
        "HSTS is relevant to HTTPS"
        in recommendation
        for recommendation
        in result["recommendations"]
    )


def test_https_reports_missing_hsts():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "https://localhost/"
        )

    assert (
        "Strict-Transport-Security"
        in result[
            "missing_security_headers"
        ]
    )


def test_all_six_present_on_https():

    headers = {
        name: "example-value"
        for name in SECURITY_HEADERS
    }

    response = make_response(
        200,
        headers,
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "https://localhost/"
        )

    assert len(
        result[
            "present_security_headers"
        ]
    ) == 6

    assert (
        result[
            "missing_security_headers"
        ]
        == []
    )


def test_missing_headers_are_observations():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "https://localhost/"
        )

    assert any(
        "not proof of a vulnerability"
        in message
        for message
        in result["recommendations"]
    )


def test_http_404_is_still_successfully_audited():

    error = make_http_error(
        404,
        {
            "X-Frame-Options":
                "DENY",
        },
    )

    with patch(
        "modules.http_headers._open_request",
        side_effect=error,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert result["success"] is True
    assert result["error"] is None
    assert result["status_code"] == 404

    assert (
        "X-Frame-Options"
        in result[
            "present_security_headers"
        ]
    )


def test_http_500_is_still_audited():

    error = make_http_error(
        500,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        side_effect=error,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert result["success"] is True
    assert result["status_code"] == 500


def test_url_error():

    error = urllib.error.URLError(
        "Connection refused"
    )

    with patch(
        "modules.http_headers._open_request",
        side_effect=error,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert result["success"] is False
    assert result["status_code"] is None
    assert result["headers"] == {}

    assert (
        "Network error"
        in result["error"]
    )


def test_raw_oserror():

    with patch(
        "modules.http_headers._open_request",
        side_effect=OSError(
            "Network unavailable"
        ),
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert result["success"] is False

    assert (
        "Request failed"
        in result["error"]
    )


def test_result_dictionary_shape_success():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert set(
        result.keys()
    ) == {
        "url",
        "status_code",
        "headers",
        "present_security_headers",
        "missing_security_headers",
        "recommendations",
        "success",
        "error",
    }


def test_result_dictionary_shape_failure():

    with patch(
        "modules.http_headers._open_request",
        side_effect=urllib.error.URLError(
            "boom"
        ),
    ):
        result = audit_http_headers(
            "http://localhost/"
        )

    assert set(
        result.keys()
    ) == {
        "url",
        "status_code",
        "headers",
        "present_security_headers",
        "missing_security_headers",
        "recommendations",
        "success",
        "error",
    }


def test_response_is_closed():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ):
        audit_http_headers(
            "http://localhost/"
        )

    response.close.assert_called_once()


def test_open_receives_timeout():

    response = make_response(
        200,
        {},
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ) as open_mock:

        audit_http_headers(
            "http://localhost/",
            timeout=2.5,
        )

    open_mock.assert_called_once()

    assert (
        open_mock.call_args.args[1]
        == 2.5
    )


def test_redirect_handler_refuses_redirect():

    handler = (
        _NoRedirectHandler()
    )

    result = handler.redirect_request(
        req=None,
        fp=None,
        code=302,
        msg="Found",
        headers={},
        newurl="https://example.com/",
    )

    assert result is None


def test_only_one_request_is_attempted():

    response = make_response(
        200,
        {
            "Link":
                "<https://example.com/next>",
        },
    )

    with patch(
        "modules.http_headers._open_request",
        return_value=response,
    ) as open_mock:

        audit_http_headers(
            "http://localhost/"
        )

    open_mock.assert_called_once()
