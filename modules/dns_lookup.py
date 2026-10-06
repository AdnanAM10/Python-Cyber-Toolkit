"""
modules/dns_lookup.py
=====================

Passive DNS lookup helpers using Python's standard library.

This module supports:

- Forward lookup: hostname -> IP addresses
- Reverse lookup: IP address -> hostname

SAFETY NOTE
-----------
DNS lookup is a basic network-information operation and does not perform
port scanning.

Later active-scanning features in this project must only be used on
systems you own or have explicit permission to test.

Standard library only:
- socket
- ipaddress
"""

import ipaddress
import socket


def forward_lookup(hostname: str) -> dict:
    """
    Resolve a hostname into IPv4 and/or IPv6 addresses.

    Returns a dictionary containing:

    hostname
    ip_addresses
    success
    error
    """

    if not isinstance(hostname, str):
        raise TypeError(
            f"forward_lookup() expects a str for 'hostname', "
            f"got {type(hostname).__name__}."
        )

    hostname = hostname.strip()

    if not hostname:
        raise ValueError(
            "forward_lookup() received an empty hostname. "
            "Pass a non-empty hostname such as 'example.com'."
        )

    try:
        records = socket.getaddrinfo(
            hostname,
            0,
        )

    except socket.gaierror as exc:
        return {
            "hostname": hostname,
            "ip_addresses": [],
            "success": False,
            "error": f"DNS resolution failed: {exc}",
        }

    except OSError as exc:
        return {
            "hostname": hostname,
            "ip_addresses": [],
            "success": False,
            "error": f"Network error: {exc}",
        }

    ip_addresses: list[str] = []
    seen: set[str] = set()

    for record in records:
        sockaddr = record[4]

        if not sockaddr:
            continue

        ip_address = sockaddr[0]

        if ip_address not in seen:
            seen.add(ip_address)
            ip_addresses.append(ip_address)

    return {
        "hostname": hostname,
        "ip_addresses": ip_addresses,
        "success": True,
        "error": None,
    }


def reverse_lookup(ip_address: str) -> dict:
    """
    Resolve an IPv4 or IPv6 address into its hostname.

    Returns a dictionary containing:

    ip_address
    hostname
    aliases
    success
    error
    """

    if not isinstance(ip_address, str):
        raise TypeError(
            f"reverse_lookup() expects a str for 'ip_address', "
            f"got {type(ip_address).__name__}."
        )

    ip_address = ip_address.strip()

    if not ip_address:
        raise ValueError(
            "reverse_lookup() received an empty IP address. "
            "Pass a valid IPv4 or IPv6 address."
        )

    # Validate the address before attempting DNS resolution.
    try:
        validated_ip = ipaddress.ip_address(
            ip_address
        )

    except ValueError:
        return {
            "ip_address": ip_address,
            "hostname": None,
            "aliases": [],
            "success": False,
            "error": "Invalid IP address.",
        }

    normalized_ip = str(
        validated_ip
    )

    try:
        canonical_name, aliases, _ = socket.gethostbyaddr(
            normalized_ip
        )

    except (
        socket.herror,
        socket.gaierror,
    ) as exc:

        return {
            "ip_address": normalized_ip,
            "hostname": None,
            "aliases": [],
            "success": False,
            "error": f"Reverse DNS failed: {exc}",
        }

    except OSError as exc:
        return {
            "ip_address": normalized_ip,
            "hostname": None,
            "aliases": [],
            "success": False,
            "error": f"Network error: {exc}",
        }

    return {
        "ip_address": normalized_ip,
        "hostname": canonical_name,
        "aliases": list(aliases),
        "success": True,
        "error": None,
    }


if __name__ == "__main__":

    print("=" * 60)
    print("DNS Lookup Demo")
    print("=" * 60)

    print("\n[1] Forward lookup: localhost")

    forward_result = forward_lookup(
        "localhost"
    )

    if forward_result["success"]:
        print(
            f"Hostname : "
            f"{forward_result['hostname']}"
        )

        print(
            "IPs      : "
            + ", ".join(
                forward_result["ip_addresses"]
            )
        )

    else:
        print(
            f"Error    : "
            f"{forward_result['error']}"
        )

    print(
        "\n[2] Reverse lookup: 127.0.0.1"
    )

    reverse_result = reverse_lookup(
        "127.0.0.1"
    )

    if reverse_result["success"]:
        print(
            f"IP       : "
            f"{reverse_result['ip_address']}"
        )

        print(
            f"Hostname : "
            f"{reverse_result['hostname']}"
        )

        if reverse_result["aliases"]:
            print(
                "Aliases  : "
                + ", ".join(
                    reverse_result["aliases"]
                )
            )

    else:
        print(
            f"Error    : "
            f"{reverse_result['error']}"
        )

    print(
        "\n[3] Invalid IP validation"
    )

    invalid_result = reverse_lookup(
        "not.an.ip"
    )

    print(
        f"Success  : "
        f"{invalid_result['success']}"
    )

    print(
        f"Error    : "
        f"{invalid_result['error']}"
    )

    print("\n" + "=" * 60)

    print(
        "Use active-scanning features only on systems "
        "you own or have permission to test."
    )

    print("=" * 60)
