# Testing Strategy

## Why Automated Testing Was Used

Automated testing was used because security and networking utilities need predictable behavior.

Tests help:

- detect regressions
- verify input validation
- verify authorization safeguards
- document expected behavior
- confirm error handling
- allow repeatable testing after changes

## Test Organization

The project includes:

- test_base64_util.py
- test_hash_gen.py
- test_password_strength.py
- test_dns_lookup.py
- test_port_scanner.py
- test_http_headers.py
- test_web_app.py

pytest.ini configures test discovery in the tests directory.

## Network Mocking Strategy

Network-related tests use unittest.mock.

DNS tests mock socket resolution behavior.

Port scanner tests mock socket creation and connections.

HTTP tests mock the module's _open_request helper.

UI tests mock imported core functions.

No real third-party systems need to be contacted during the automated test suite.

## Safety Testing

Tests verify:

- unauthorized scans are rejected
- non-Boolean truthy values do not bypass authorization
- non-local HTTP auditing requires authorization
- unsupported URL schemes are rejected
- redirects are not automatically followed
- passwords do not appear in output

## Input Validation Testing

Validation tests cover:

- empty strings
- wrong input types
- invalid Base64
- unsupported hash algorithms
- invalid IP addresses
- invalid ports
- ports outside 1 through 65535
- invalid URLs
- invalid timeout values

## Running All Tests

    python -m pytest

## Running One Test File

    python -m pytest tests\test_port_scanner.py -v

## Running One Test

    python -m pytest tests\test_port_scanner.py::test_authorization_required -v

## Testing the Gradio Layer

    python -m pytest tests\test_web_app.py -v

The tests construct the application but do not intentionally launch a real Gradio server.

## Manual Smoke Testing

Start the app:

    python main.py

Then open:

    http://127.0.0.1:7860

## Summary

The test suite is designed to be repeatable, deterministic, quick, safe, and independent of public network availability.
