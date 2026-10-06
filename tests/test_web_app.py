"""
Tests for ui/web_app.py.

No Gradio server is launched.
Network-related module calls are mocked.
"""

from unittest.mock import MagicMock, patch

import pytest

from ui import web_app


def test_base64_encode_wrapper():

    result = web_app.ui_base64_encode(
        "Hello, World!"
    )

    assert result["success"] is True

    assert (
        result["encoded"]
        == "SGVsbG8sIFdvcmxkIQ=="
    )


def test_base64_decode_wrapper():

    result = web_app.ui_base64_decode(
        "SGVsbG8sIFdvcmxkIQ=="
    )

    assert result["success"] is True

    assert (
        result["decoded"]
        == "Hello, World!"
    )


def test_base64_invalid_input_is_friendly():

    result = web_app.ui_base64_decode(
        "!!!bad-base64!!!"
    )

    assert result["success"] is False
    assert "error" in result
    assert "Traceback" not in result["error"]


def test_hash_wrapper():

    result = web_app.ui_generate_hash(
        "hello",
        "sha256",
    )

    assert result["success"] is True
    assert result["algorithm"] == "sha256"
    assert len(result["hash"]) == 64


def test_hash_invalid_algorithm():

    result = web_app.ui_generate_hash(
        "hello",
        "not-real",
    )

    assert result["success"] is False
    assert "error" in result


def test_password_wrapper():

    result = web_app.ui_check_password(
        "ExamplePassword123!"
    )

    assert result["success"] is True
    assert "score" in result
    assert "rating" in result
    assert "strengths" in result
    assert "suggestions" in result


def test_password_not_echoed():

    secret = "VerySecretPassword123!"

    result = web_app.ui_check_password(
        secret
    )

    assert secret not in str(
        result
    )


def test_password_empty_error():

    result = web_app.ui_check_password(
        ""
    )

    assert result["success"] is False
    assert "error" in result


@patch(
    "ui.web_app.forward_lookup"
)
def test_dns_forward_wrapper(
    mock_forward,
):

    mock_forward.return_value = {
        "hostname": "example.com",
        "ip_addresses": [
            "192.0.2.1"
        ],
        "success": True,
        "error": None,
    }

    result = web_app.ui_dns_forward(
        "example.com"
    )

    mock_forward.assert_called_once_with(
        "example.com"
    )

    assert result["success"] is True


@patch(
    "ui.web_app.reverse_lookup"
)
def test_dns_reverse_wrapper(
    mock_reverse,
):

    mock_reverse.return_value = {
        "ip_address": "127.0.0.1",
        "hostname": "localhost",
        "aliases": [],
        "success": True,
        "error": None,
    }

    result = web_app.ui_dns_reverse(
        "127.0.0.1"
    )

    mock_reverse.assert_called_once_with(
        "127.0.0.1"
    )

    assert result["success"] is True


def test_parse_ports():

    assert web_app._parse_ports(
        "80, 443, 8080"
    ) == [
        80,
        443,
        8080,
    ]


def test_parse_ports_blank():

    assert web_app._parse_ports(
        ""
    ) is None


def test_parse_ports_invalid():

    with pytest.raises(
        ValueError,
        match="not a valid port",
    ):
        web_app._parse_ports(
            "80, abc"
        )


@patch(
    "ui.web_app.scan_ports"
)
def test_port_wrapper_authorized(
    mock_scan,
):

    mock_scan.return_value = {
        "success": True
    }

    result = web_app.ui_scan_ports(
        "127.0.0.1",
        "80,443",
        1.0,
        True,
    )

    mock_scan.assert_called_once_with(
        "127.0.0.1",
        [
            80,
            443,
        ],
        authorized=True,
        timeout=1.0,
    )

    assert result["success"] is True


@patch(
    "ui.web_app.scan_ports"
)
def test_port_wrapper_unchecked(
    mock_scan,
):

    mock_scan.side_effect = PermissionError(
        "Scan not permitted."
    )

    result = web_app.ui_scan_ports(
        "example.com",
        "80",
        1.0,
        False,
    )

    mock_scan.assert_called_once_with(
        "example.com",
        [
            80
        ],
        authorized=False,
        timeout=1.0,
    )

    assert result["success"] is False

    assert (
        "Authorization required"
        in result["error"]
    )


@patch(
    "ui.web_app.scan_ports"
)
def test_truthy_string_not_authorized(
    mock_scan,
):

    mock_scan.side_effect = PermissionError(
        "Scan not permitted."
    )

    web_app.ui_scan_ports(
        "example.com",
        "80",
        1.0,
        "True",
    )

    mock_scan.assert_called_once_with(
        "example.com",
        [
            80
        ],
        authorized=False,
        timeout=1.0,
    )


@patch(
    "ui.web_app.audit_http_headers"
)
def test_http_local_wrapper(
    mock_audit,
):

    mock_audit.return_value = {
        "success": True
    }

    result = web_app.ui_audit_http(
        "http://127.0.0.1:8000/",
        False,
        10.0,
    )

    mock_audit.assert_called_once_with(
        "http://127.0.0.1:8000/",
        authorized=False,
        timeout=10.0,
    )

    assert result["success"] is True


@patch(
    "ui.web_app.audit_http_headers"
)
def test_http_nonlocal_unchecked(
    mock_audit,
):

    mock_audit.side_effect = PermissionError(
        "Non-local target refused."
    )

    result = web_app.ui_audit_http(
        "https://example.com/",
        False,
        10.0,
    )

    assert result["success"] is False

    assert (
        "Authorization required"
        in result["error"]
    )


@patch(
    "ui.web_app.audit_http_headers"
)
def test_http_nonlocal_authorized(
    mock_audit,
):

    mock_audit.return_value = {
        "success": True
    }

    result = web_app.ui_audit_http(
        "https://example.com/",
        True,
        10.0,
    )

    mock_audit.assert_called_once_with(
        "https://example.com/",
        authorized=True,
        timeout=10.0,
    )

    assert result["success"] is True


def test_build_app_missing_gradio():

    with patch(
        "ui.web_app._GRADIO_AVAILABLE",
        False,
    ):

        with pytest.raises(
            RuntimeError,
            match="Gradio is not installed",
        ):
            web_app.build_app()


@pytest.mark.skipif(
    not web_app._GRADIO_AVAILABLE,
    reason="Gradio is not installed",
)
def test_build_app_constructs_blocks():

    app = web_app.build_app()

    assert app is not None

    assert (
        app.__class__.__name__
        == "Blocks"
    )


def test_main_launch_configuration():

    fake_app = MagicMock()

    with patch(
        "ui.web_app.build_app",
        return_value=fake_app,
    ):

        web_app.main()

    fake_app.launch.assert_called_once_with(
        server_name="127.0.0.1",
        server_port=7860,
        share=False,
    )
