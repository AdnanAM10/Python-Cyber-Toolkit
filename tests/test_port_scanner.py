"""
Tests for modules/port_scanner.py.

All network operations are mocked.
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from modules.port_scanner import (
    DEFAULT_PORTS,
    _check_port,
    scan_ports,
)


def make_socket(
    *,
    connection_error=None,
) -> MagicMock:
    """
    Build a mocked socket.

    If connection_error is None, connect() succeeds.
    Otherwise connect() raises the supplied exception.
    """

    sock = MagicMock()

    if connection_error is None:
        sock.connect.return_value = None
    else:
        sock.connect.side_effect = connection_error

    return sock


def test_authorization_required():

    with patch(
        "modules.port_scanner.socket.gethostbyname"
    ) as resolver, patch(
        "modules.port_scanner.socket.socket"
    ) as socket_mock:

        with pytest.raises(
            PermissionError,
            match="authorized",
        ):
            scan_ports(
                "127.0.0.1",
                [80],
            )

        resolver.assert_not_called()
        socket_mock.assert_not_called()


@pytest.mark.parametrize(
    "authorization",
    [
        False,
        None,
        1,
        "True",
    ],
)
def test_invalid_authorization_values(
    authorization,
):

    with pytest.raises(
        PermissionError
    ):
        scan_ports(
            "127.0.0.1",
            [80],
            authorized=authorization,
        )


def test_target_must_be_string():

    with pytest.raises(
        TypeError,
        match="expects a str",
    ):
        scan_ports(
            12345,
            [80],
            authorized=True,
        )


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
    ],
)
def test_empty_target_rejected(
    target,
):

    with pytest.raises(
        ValueError,
        match="empty target",
    ):
        scan_ports(
            target,
            [80],
            authorized=True,
        )


@pytest.mark.parametrize(
    "port",
    [
        0,
        -1,
        65536,
        70000,
    ],
)
def test_out_of_range_ports_rejected(
    port,
):

    with pytest.raises(
        ValueError,
        match="out of range",
    ):
        scan_ports(
            "127.0.0.1",
            [port],
            authorized=True,
        )


@pytest.mark.parametrize(
    "port",
    [
        "80",
        80.0,
        True,
    ],
)
def test_non_integer_ports_rejected(
    port,
):

    with pytest.raises(
        TypeError,
        match="must be an integer",
    ):
        scan_ports(
            "127.0.0.1",
            [port],
            authorized=True,
        )


def test_invalid_ports_container_rejected():

    with pytest.raises(
        TypeError,
        match="list, tuple, int, or None",
    ):
        scan_ports(
            "127.0.0.1",
            "80,443",
            authorized=True,
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
        match="greater than 0",
    ):
        scan_ports(
            "127.0.0.1",
            [80],
            authorized=True,
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
        match="positive number",
    ):
        scan_ports(
            "127.0.0.1",
            [80],
            authorized=True,
            timeout=timeout,
        )


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_single_integer_port(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.return_value = (
        make_socket()
    )

    result = scan_ports(
        "127.0.0.1",
        80,
        authorized=True,
    )

    assert result["scanned_ports"] == [
        80
    ]

    assert result["open_ports"] == [
        80
    ]


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_duplicate_ports_removed(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.side_effect = [
        make_socket(),
        make_socket(),
        make_socket(),
    ]

    result = scan_ports(
        "127.0.0.1",
        [
            80,
            80,
            22,
            22,
            443,
        ],
        authorized=True,
    )

    assert result["scanned_ports"] == [
        80,
        22,
        443,
    ]

    assert socket_mock.call_count == 3


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_duplicate_removal_preserves_order(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.side_effect = [
        make_socket(),
        make_socket(),
        make_socket(),
    ]

    result = scan_ports(
        "127.0.0.1",
        [
            443,
            80,
            22,
            80,
            443,
        ],
        authorized=True,
    )

    assert result["scanned_ports"] == [
        443,
        80,
        22,
    ]


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_open_port_detected(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.return_value = (
        make_socket()
    )

    result = scan_ports(
        "127.0.0.1",
        [80],
        authorized=True,
    )

    assert result["success"] is True
    assert result["open_ports"] == [80]
    assert result["closed_ports"] == []
    assert result["errors"] == {}


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_closed_port_detected(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.return_value = (
        make_socket(
            connection_error=ConnectionRefusedError(
                "Connection refused"
            )
        )
    )

    result = scan_ports(
        "127.0.0.1",
        [9999],
        authorized=True,
    )

    assert result["open_ports"] == []

    assert result["closed_ports"] == [
        9999
    ]

    assert (
        result["errors"][9999]
        == "Connection refused"
    )


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_mixed_ports(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.side_effect = [
        make_socket(),
        make_socket(
            connection_error=ConnectionRefusedError(
                "Connection refused"
            )
        ),
    ]

    result = scan_ports(
        "127.0.0.1",
        [
            80,
            443,
        ],
        authorized=True,
    )

    assert result["open_ports"] == [
        80
    ]

    assert result["closed_ports"] == [
        443
    ]


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_dns_failure_does_not_scan(
    socket_mock,
    resolver,
):

    resolver.side_effect = socket.gaierror(
        "Unknown host"
    )

    result = scan_ports(
        "bad.invalid",
        [80],
        authorized=True,
    )

    assert result["success"] is False
    assert result["resolved_ip"] is None
    assert result["scanned_ports"] == []
    assert result["open_ports"] == []
    assert result["closed_ports"] == []

    assert (
        "DNS resolution failed"
        in result["error"]
    )

    socket_mock.assert_not_called()


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
def test_resolution_oserror(
    resolver,
):

    resolver.side_effect = OSError(
        "Network unreachable"
    )

    result = scan_ports(
        "example.com",
        [80],
        authorized=True,
    )

    assert result["success"] is False

    assert (
        "Resolution error"
        in result["error"]
    )


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_socket_timeout_recorded(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    sock = make_socket(
        connection_error=socket.timeout(
            "timed out"
        )
    )

    socket_mock.return_value = (
        sock
    )

    result = scan_ports(
        "127.0.0.1",
        [80],
        authorized=True,
        timeout=0.1,
    )

    assert result["success"] is True

    assert result["closed_ports"] == [
        80
    ]

    assert (
        "timed out"
        in result["errors"][80].lower()
    )

    sock.close.assert_called_once()


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_socket_oserror_recorded(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    sock = make_socket(
        connection_error=OSError(
            "Network unreachable"
        )
    )

    socket_mock.return_value = (
        sock
    )

    result = scan_ports(
        "127.0.0.1",
        [80],
        authorized=True,
    )

    assert result["closed_ports"] == [
        80
    ]

    assert (
        "Network unreachable"
        in result["errors"][80]
    )

    sock.close.assert_called_once()


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_connect_called_with_correct_address(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    sock = make_socket()

    socket_mock.return_value = (
        sock
    )

    scan_ports(
        "127.0.0.1",
        [443],
        authorized=True,
    )

    sock.connect.assert_called_once_with(
        (
            "127.0.0.1",
            443,
        )
    )


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_settimeout_receives_value(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    sock = make_socket()

    socket_mock.return_value = (
        sock
    )

    scan_ports(
        "127.0.0.1",
        [80],
        authorized=True,
        timeout=0.25,
    )

    sock.settimeout.assert_called_once_with(
        0.25
    )


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_socket_always_closed(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    sock = make_socket()

    socket_mock.return_value = (
        sock
    )

    scan_ports(
        "127.0.0.1",
        [80],
        authorized=True,
    )

    sock.close.assert_called_once()


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_result_dictionary_shape(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.return_value = (
        make_socket()
    )

    result = scan_ports(
        "127.0.0.1",
        [80],
        authorized=True,
    )

    assert set(
        result.keys()
    ) == {
        "target",
        "resolved_ip",
        "scanned_ports",
        "open_ports",
        "closed_ports",
        "errors",
        "error",
        "success",
    }


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_default_ports(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.side_effect = [
        make_socket()
        for _ in DEFAULT_PORTS
    ]

    result = scan_ports(
        "127.0.0.1",
        authorized=True,
    )

    assert result["scanned_ports"] == (
        DEFAULT_PORTS
    )

    assert len(
        result["open_ports"]
    ) == len(
        DEFAULT_PORTS
    )


@patch(
    "modules.port_scanner.socket.gethostbyname"
)
@patch(
    "modules.port_scanner.socket.socket"
)
def test_target_whitespace_is_removed(
    socket_mock,
    resolver,
):

    resolver.return_value = (
        "127.0.0.1"
    )

    socket_mock.return_value = (
        make_socket()
    )

    result = scan_ports(
        "  127.0.0.1  ",
        [80],
        authorized=True,
    )

    assert (
        result["target"]
        == "127.0.0.1"
    )

    resolver.assert_called_once_with(
        "127.0.0.1"
    )


def test_check_port_handles_socket_creation_error():

    with patch(
        "modules.port_scanner.socket.socket",
        side_effect=OSError(
            "Socket creation failed"
        ),
    ):

        is_open, error = _check_port(
            "127.0.0.1",
            80,
            1.0,
        )

    assert is_open is False

    assert (
        "Socket creation failed"
        in error
    )


def test_check_port_handles_settimeout_error():

    sock = MagicMock()

    sock.settimeout.side_effect = OSError(
        "Timeout configuration failed"
    )

    with patch(
        "modules.port_scanner.socket.socket",
        return_value=sock,
    ):

        is_open, error = _check_port(
            "127.0.0.1",
            80,
            1.0,
        )

    assert is_open is False

    assert (
        "Timeout configuration failed"
        in error
    )

    sock.close.assert_called_once()
