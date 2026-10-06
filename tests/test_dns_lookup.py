"""
Unit tests for modules/dns_lookup.py.

Socket DNS functions are mocked so the tests do not depend on
public DNS or an internet connection.
"""

import socket
from unittest.mock import patch

import pytest

from modules.dns_lookup import (
    forward_lookup,
    reverse_lookup,
)


def make_addrinfo(
    ip: str,
    family: int = socket.AF_INET,
    socktype: int = socket.SOCK_STREAM,
    proto: int = 6,
    port: int = 0,
):
    """
    Build a fake socket.getaddrinfo() result.
    """

    if family == socket.AF_INET6:
        sockaddr = (
            ip,
            port,
            0,
            0,
        )

    else:
        sockaddr = (
            ip,
            port,
        )

    return (
        family,
        socktype,
        proto,
        "",
        sockaddr,
    )


def test_forward_rejects_non_string():
    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        forward_lookup(
            12345
        )


def test_forward_rejects_empty_string():
    with pytest.raises(
        ValueError,
        match="empty hostname",
    ):
        forward_lookup(
            ""
        )


def test_forward_rejects_whitespace_only():
    with pytest.raises(
        ValueError,
        match="empty hostname",
    ):
        forward_lookup(
            "   "
        )


def test_reverse_rejects_non_string():
    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        reverse_lookup(
            12345
        )


def test_reverse_rejects_empty_string():
    with pytest.raises(
        ValueError,
        match="empty IP address",
    ):
        reverse_lookup(
            ""
        )


def test_reverse_rejects_whitespace_only():
    with pytest.raises(
        ValueError,
        match="empty IP address",
    ):
        reverse_lookup(
            "   "
        )


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_lookup_single_ipv4(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "192.0.2.1"
        )
    ]

    result = forward_lookup(
        "example.com"
    )

    assert result["success"] is True
    assert result["error"] is None
    assert result["hostname"] == "example.com"

    assert result["ip_addresses"] == [
        "192.0.2.1"
    ]


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_lookup_ipv4_and_ipv6(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "192.0.2.1"
        ),
        make_addrinfo(
            "2001:db8::1",
            family=socket.AF_INET6,
        ),
    ]

    result = forward_lookup(
        "example.com"
    )

    assert result["success"] is True

    assert result["ip_addresses"] == [
        "192.0.2.1",
        "2001:db8::1",
    ]


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_lookup_deduplicates_ips(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "192.0.2.1",
            socktype=socket.SOCK_STREAM,
        ),
        make_addrinfo(
            "192.0.2.1",
            socktype=socket.SOCK_DGRAM,
            proto=17,
        ),
        make_addrinfo(
            "192.0.2.2"
        ),
    ]

    result = forward_lookup(
        "example.com"
    )

    assert result["ip_addresses"] == [
        "192.0.2.1",
        "192.0.2.2",
    ]


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_lookup_preserves_order(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "10.0.0.3"
        ),
        make_addrinfo(
            "10.0.0.1"
        ),
        make_addrinfo(
            "10.0.0.2"
        ),
    ]

    result = forward_lookup(
        "example.com"
    )

    assert result["ip_addresses"] == [
        "10.0.0.3",
        "10.0.0.1",
        "10.0.0.2",
    ]


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_strips_whitespace(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "192.0.2.1"
        )
    ]

    result = forward_lookup(
        "  example.com  "
    )

    assert result["hostname"] == "example.com"

    mock_getaddrinfo.assert_called_once_with(
        "example.com",
        0,
    )


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_resolution_failure(
    mock_getaddrinfo,
):
    mock_getaddrinfo.side_effect = socket.gaierror(
        "Name or service not known"
    )

    result = forward_lookup(
        "no-such-host.invalid"
    )

    assert result["success"] is False
    assert result["ip_addresses"] == []

    assert (
        "DNS resolution failed"
        in result["error"]
    )


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_network_error(
    mock_getaddrinfo,
):
    mock_getaddrinfo.side_effect = OSError(
        "Network unreachable"
    )

    result = forward_lookup(
        "example.com"
    )

    assert result["success"] is False

    assert (
        "Network error"
        in result["error"]
    )


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_empty_result(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = []

    result = forward_lookup(
        "example.com"
    )

    assert result["success"] is True
    assert result["ip_addresses"] == []
    assert result["error"] is None


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
def test_forward_return_shape(
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "192.0.2.1"
        )
    ]

    result = forward_lookup(
        "example.com"
    )

    assert set(result.keys()) == {
        "hostname",
        "ip_addresses",
        "success",
        "error",
    }

    assert isinstance(
        result["ip_addresses"],
        list,
    )

    assert isinstance(
        result["success"],
        bool,
    )


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_lookup_ipv4(
    mock_gethostbyaddr,
):
    mock_gethostbyaddr.return_value = (
        "localhost",
        [],
        ["127.0.0.1"],
    )

    result = reverse_lookup(
        "127.0.0.1"
    )

    assert result["success"] is True
    assert result["error"] is None

    assert (
        result["ip_address"]
        == "127.0.0.1"
    )

    assert (
        result["hostname"]
        == "localhost"
    )

    assert result["aliases"] == []


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_lookup_ipv6(
    mock_gethostbyaddr,
):
    mock_gethostbyaddr.return_value = (
        "localhost",
        [],
        ["::1"],
    )

    result = reverse_lookup(
        "::1"
    )

    assert result["success"] is True
    assert result["ip_address"] == "::1"
    assert result["hostname"] == "localhost"


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_lookup_aliases(
    mock_gethostbyaddr,
):
    original_aliases = [
        "host",
        "host-alias",
    ]

    mock_gethostbyaddr.return_value = (
        "host.example.com",
        original_aliases,
        ["192.0.2.50"],
    )

    result = reverse_lookup(
        "192.0.2.50"
    )

    assert result["success"] is True

    assert (
        result["hostname"]
        == "host.example.com"
    )

    assert result["aliases"] == [
        "host",
        "host-alias",
    ]

    assert (
        result["aliases"]
        is not original_aliases
    )


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_strips_whitespace(
    mock_gethostbyaddr,
):
    mock_gethostbyaddr.return_value = (
        "localhost",
        [],
        ["127.0.0.1"],
    )

    result = reverse_lookup(
        "  127.0.0.1  "
    )

    assert (
        result["ip_address"]
        == "127.0.0.1"
    )

    mock_gethostbyaddr.assert_called_once_with(
        "127.0.0.1"
    )


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_dns_failure(
    mock_gethostbyaddr,
):
    mock_gethostbyaddr.side_effect = socket.herror(
        "Name does not resolve"
    )

    result = reverse_lookup(
        "192.0.2.254"
    )

    assert result["success"] is False
    assert result["hostname"] is None
    assert result["aliases"] == []

    assert (
        "Reverse DNS failed"
        in result["error"]
    )


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_network_error(
    mock_gethostbyaddr,
):
    mock_gethostbyaddr.side_effect = OSError(
        "Network unreachable"
    )

    result = reverse_lookup(
        "192.0.2.1"
    )

    assert result["success"] is False

    assert (
        "Network error"
        in result["error"]
    )


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_invalid_ip_does_not_query_dns(
    mock_gethostbyaddr,
):
    result = reverse_lookup(
        "not.an.ip"
    )

    assert result["success"] is False
    assert result["hostname"] is None
    assert result["aliases"] == []

    assert result["error"] == (
        "Invalid IP address."
    )

    mock_gethostbyaddr.assert_not_called()


@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_reverse_return_shape(
    mock_gethostbyaddr,
):
    mock_gethostbyaddr.return_value = (
        "localhost",
        [],
        ["127.0.0.1"],
    )

    result = reverse_lookup(
        "127.0.0.1"
    )

    assert set(result.keys()) == {
        "ip_address",
        "hostname",
        "aliases",
        "success",
        "error",
    }

    assert isinstance(
        result["aliases"],
        list,
    )

    assert isinstance(
        result["success"],
        bool,
    )


@patch(
    "modules.dns_lookup.socket.getaddrinfo"
)
@patch(
    "modules.dns_lookup.socket.gethostbyaddr"
)
def test_both_functions_share_status_keys(
    mock_gethostbyaddr,
    mock_getaddrinfo,
):
    mock_getaddrinfo.return_value = [
        make_addrinfo(
            "192.0.2.1"
        )
    ]

    mock_gethostbyaddr.return_value = (
        "localhost",
        [],
        ["127.0.0.1"],
    )

    forward_result = forward_lookup(
        "example.com"
    )

    reverse_result = reverse_lookup(
        "127.0.0.1"
    )

    for key in (
        "success",
        "error",
    ):
        assert key in forward_result
        assert key in reverse_result
