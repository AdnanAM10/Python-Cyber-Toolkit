"""
modules/port_scanner.py
=======================

Sequential TCP connect port scanner for educational use.

SAFETY
------
Only scan systems that you own or have explicit permission to test.

This scanner:
- requires authorized=True
- scans one target at a time
- performs TCP connect checks only
- does not perform banner grabbing
- does not fingerprint services or operating systems
- does not exploit vulnerabilities
- does not use stealth or evasion techniques

Standard library only: socket
"""

import socket


DEFAULT_PORTS: list[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    993,
    995,
    3306,
    8080,
    8443,
]

MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_TIMEOUT = 1.0


def _check_port(
    ip_address: str,
    port: int,
    timeout: float,
) -> tuple[bool, str | None]:
    """
    Attempt one TCP connection.

    Returns:
        (True, None) if open
        (False, message) otherwise
    """

    sock = None

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(timeout)

        sock.connect(
            (
                ip_address,
                port,
            )
        )

        return True, None

    except ConnectionRefusedError:
        return (
            False,
            "Connection refused",
        )

    except socket.timeout:
        return (
            False,
            "Connection timed out",
        )

    except OSError as exc:
        return (
            False,
            str(exc),
        )

    finally:
        if sock is not None:
            sock.close()


def _normalize_ports(
    ports: list[int] | tuple[int, ...] | int | None,
) -> list[int]:
    """
    Validate and deduplicate ports while preserving order.
    """

    if ports is None:
        port_list = list(
            DEFAULT_PORTS
        )

    elif (
        isinstance(ports, int)
        and not isinstance(ports, bool)
    ):
        port_list = [
            ports
        ]

    elif isinstance(
        ports,
        (list, tuple),
    ):
        port_list = list(
            ports
        )

    else:
        raise TypeError(
            "scan_ports() 'ports' must be a list, tuple, int, or None."
        )

    for port in port_list:

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
        ):
            raise TypeError(
                f"Every port must be an integer, got "
                f"{type(port).__name__} ({port!r})."
            )

        if (
            port < MIN_PORT
            or port > MAX_PORT
        ):
            raise ValueError(
                f"Port {port} is out of range. "
                f"Valid ports are {MIN_PORT} to {MAX_PORT}."
            )

    unique_ports: list[int] = []
    seen: set[int] = set()

    for port in port_list:
        if port not in seen:
            seen.add(port)
            unique_ports.append(
                port
            )

    return unique_ports


def scan_ports(
    target: str,
    ports: list[int] | tuple[int, ...] | int | None = None,
    authorized: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """
    Perform a sequential TCP connect scan.

    The caller must explicitly pass authorized=True.
    """

    # Authorization is intentionally checked before anything else.
    if authorized is not True:
        raise PermissionError(
            "Scan not permitted. This tool may only be used on "
            "systems you own or have explicit permission to test. "
            "Pass authorized=True only when that is true."
        )

    if not isinstance(
        target,
        str,
    ):
        raise TypeError(
            f"scan_ports() expects a str for 'target', "
            f"got {type(target).__name__}."
        )

    target = target.strip()

    if not target:
        raise ValueError(
            "scan_ports() received an empty target. "
            "Pass a hostname or IP address."
        )

    if (
        isinstance(timeout, bool)
        or not isinstance(
            timeout,
            (int, float),
        )
    ):
        raise TypeError(
            "timeout must be a positive number."
        )

    timeout = float(
        timeout
    )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    requested_ports = _normalize_ports(
        ports
    )

    try:
        resolved_ip = socket.gethostbyname(
            target
        )

    except socket.gaierror as exc:
        return {
            "target": target,
            "resolved_ip": None,
            "scanned_ports": [],
            "open_ports": [],
            "closed_ports": [],
            "errors": {},
            "error": (
                f"DNS resolution failed: {exc}"
            ),
            "success": False,
        }

    except OSError as exc:
        return {
            "target": target,
            "resolved_ip": None,
            "scanned_ports": [],
            "open_ports": [],
            "closed_ports": [],
            "errors": {},
            "error": (
                f"Resolution error: {exc}"
            ),
            "success": False,
        }

    scanned_ports: list[int] = []
    open_ports: list[int] = []
    closed_ports: list[int] = []
    errors: dict[int, str] = {}

    for port in requested_ports:

        scanned_ports.append(
            port
        )

        is_open, error_message = _check_port(
            resolved_ip,
            port,
            timeout,
        )

        if is_open:
            open_ports.append(
                port
            )

        else:
            closed_ports.append(
                port
            )

            if error_message is not None:
                errors[port] = (
                    error_message
                )

    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "scanned_ports": scanned_ports,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "errors": errors,
        "error": None,
        "success": True,
    }


if __name__ == "__main__":

    target = "127.0.0.1"

    demo_ports = [
        22,
        80,
        443,
        8080,
    ]

    print(
        "=" * 60
    )

    print(
        "TCP Port Scanner Demo"
    )

    print(
        "=" * 60
    )

    print(
        f"Target     : {target}"
    )

    print(
        f"Ports      : {demo_ports}"
    )

    print(
        "Authorized : True"
    )

    print()

    result = scan_ports(
        target,
        ports=demo_ports,
        authorized=True,
        timeout=1.0,
    )

    print(
        f"Resolved IP : {result['resolved_ip']}"
    )

    print(
        f"Ports tried : {result['scanned_ports']}"
    )

    print(
        f"Open ports  : {result['open_ports']}"
    )

    print(
        f"Closed ports: {result['closed_ports']}"
    )

    if result["errors"]:
        print(
            "\nPer-port results:"
        )

        for port, message in result["errors"].items():
            print(
                f"  {port}: {message}"
            )

    print()

    print(
        "Use active scanning only on systems you own "
        "or have permission to test."
    )

