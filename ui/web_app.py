"""
ui/web_app.py
=============

Gradio web interface for the Personal Ethical Hacking Toolkit.

This file is only the presentation layer. Core functionality remains
inside modules/.

SAFETY
------
- Port scanning requires explicit authorization.
- Non-local HTTP header auditing requires explicit authorization.
- The app binds only to 127.0.0.1.
- Public Gradio sharing is disabled.
- No passwords, history, scans, or results are stored.
"""

import os
import sys


PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(
        0,
        PROJECT_ROOT,
    )


from modules.base64_util import (
    decode_base64,
    encode_base64,
)

from modules.dns_lookup import (
    forward_lookup,
    reverse_lookup,
)

from modules.hash_gen import (
    hash_data,
    list_supported_algorithms,
)

from modules.http_headers import (
    audit_http_headers,
)

from modules.password_strength import (
    check_password_strength,
)

from modules.port_scanner import (
    scan_ports,
)


try:
    import gradio as gr
    _GRADIO_AVAILABLE = True
except ImportError:
    gr = None
    _GRADIO_AVAILABLE = False


TITLE = "Personal Ethical Hacking Toolkit"

DISCLAIMER_MD = """
## Educational / Authorized-Use Notice

This toolkit is for **learning** and for testing systems that you own
or have explicit permission to test.

- Port scanning is an active network operation.
- Non-local HTTP auditing should only be used with authorization.
- Findings are educational observations, not proof of vulnerability.
- Passwords and results are not intentionally stored by this application.

Only use the network features on systems you are authorized to test.
"""

PORT_SAFETY_MD = """
> **Authorization required:** Port scanning creates TCP connection
> attempts. Only scan systems you own or have explicit permission
> to test.
"""

HTTP_SAFETY_MD = """
> **Authorization:** Loopback URLs such as `localhost`,
> `127.0.0.1`, and `::1` can be checked without the box.
> Any non-local target requires permission and the authorization box.
"""


def _unexpected_error() -> dict:
    return {
        "success": False,
        "error": "Unexpected error. Please review the input and try again.",
    }


def ui_base64_encode(text: str) -> dict:
    try:
        return {
            "success": True,
            "encoded": encode_base64(text),
        }
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }
    except Exception:
        return _unexpected_error()


def ui_base64_decode(text: str) -> dict:
    try:
        return {
            "success": True,
            "decoded": decode_base64(text),
        }
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }
    except Exception:
        return _unexpected_error()


def ui_generate_hash(text: str, algorithm: str) -> dict:
    try:
        digest = hash_data(
            text,
            algorithm,
        )

        return {
            "success": True,
            "algorithm": algorithm,
            "hash": digest,
        }
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }
    except Exception:
        return _unexpected_error()


def ui_check_password(password: str) -> dict:
    try:
        result = check_password_strength(
            password
        )

        return {
            "success": True,
            **result,
        }
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }
    except Exception:
        return _unexpected_error()


def ui_dns_forward(hostname: str) -> dict:
    try:
        return forward_lookup(
            hostname
        )
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }
    except Exception:
        return _unexpected_error()


def ui_dns_reverse(ip_address: str) -> dict:
    try:
        return reverse_lookup(
            ip_address
        )
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }
    except Exception:
        return _unexpected_error()


def _parse_ports(
    ports_text: str,
) -> list[int] | None:

    if not isinstance(
        ports_text,
        str,
    ):
        raise ValueError(
            "Ports must be entered as text, for example: 80, 443."
        )

    text = ports_text.strip()

    if not text:
        return None

    ports: list[int] = []

    for part in text.split(","):

        part = part.strip()

        if not part:
            continue

        if not part.isdigit():
            raise ValueError(
                f"'{part}' is not a valid port number."
            )

        ports.append(
            int(part)
        )

    return ports if ports else None


def ui_scan_ports(
    target: str,
    ports_text: str,
    timeout: float,
    authorized: bool,
) -> dict:

    try:
        port_list = _parse_ports(
            ports_text
        )
    except ValueError as exc:
        return {
            "success": False,
            "target": target,
            "error": str(exc),
        }

    is_authorized = (
        authorized is True
    )

    try:
        return scan_ports(
            target,
            port_list,
            authorized=is_authorized,
            timeout=timeout,
        )

    except PermissionError as exc:
        return {
            "success": False,
            "target": target,
            "error": f"Authorization required: {exc}",
        }

    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "target": target,
            "error": str(exc),
        }

    except Exception:
        return {
            "success": False,
            "target": target,
            "error": "Unexpected error. Please review the input and try again.",
        }


def ui_audit_http(
    url: str,
    authorized: bool,
    timeout: float,
) -> dict:

    is_authorized = (
        authorized is True
    )

    try:
        return audit_http_headers(
            url,
            authorized=is_authorized,
            timeout=timeout,
        )

    except PermissionError as exc:
        return {
            "success": False,
            "url": url,
            "error": f"Authorization required: {exc}",
        }

    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "url": url,
            "error": str(exc),
        }

    except Exception:
        return {
            "success": False,
            "url": url,
            "error": "Unexpected error. Please review the input and try again.",
        }


def _tab_base64():
    with gr.Tab("Base64"):

        gr.Markdown(
            "Encode or decode Base64 text. "
            "**Base64 is encoding, not encryption.**"
        )

        with gr.Row():

            with gr.Column():

                encode_input = gr.Textbox(
                    label="Text to encode",
                    placeholder="Hello, World!",
                )

                encode_output = gr.JSON(
                    label="Encoded result"
                )

                encode_button = gr.Button(
                    "Encode"
                )

                encode_button.click(
                    fn=ui_base64_encode,
                    inputs=encode_input,
                    outputs=encode_output,
                )

            with gr.Column():

                decode_input = gr.Textbox(
                    label="Base64 to decode",
                    placeholder="SGVsbG8sIFdvcmxkIQ==",
                )

                decode_output = gr.JSON(
                    label="Decoded result"
                )

                decode_button = gr.Button(
                    "Decode"
                )

                decode_button.click(
                    fn=ui_base64_decode,
                    inputs=decode_input,
                    outputs=decode_output,
                )


def _tab_hash():
    with gr.Tab("Hash Generator"):

        gr.Markdown(
            "Generate educational hash examples. "
            "**MD5 and SHA-1 are included only for historical comparison.**"
        )

        text_input = gr.Textbox(
            label="Text to hash",
            placeholder="hello",
        )

        algorithm = gr.Dropdown(
            choices=list_supported_algorithms(),
            value="sha256",
            label="Algorithm",
        )

        output = gr.JSON(
            label="Hash result"
        )

        button = gr.Button(
            "Generate hash"
        )

        button.click(
            fn=ui_generate_hash,
            inputs=[
                text_input,
                algorithm,
            ],
            outputs=output,
        )


def _tab_password():
    with gr.Tab("Password Strength"):

        gr.Markdown(
            "Evaluate a password using the project's transparent rule-based "
            "heuristic. The password is **not echoed in the result**."
        )

        password = gr.Textbox(
            label="Password",
            type="password",
            placeholder="Enter password",
        )

        output = gr.JSON(
            label="Strength result"
        )

        button = gr.Button(
            "Check strength"
        )

        button.click(
            fn=ui_check_password,
            inputs=password,
            outputs=output,
        )


def _tab_dns():
    with gr.Tab("DNS Lookup"):

        gr.Markdown(
            "Forward and reverse DNS lookup using Python's socket module."
        )

        with gr.Row():

            with gr.Column():

                hostname = gr.Textbox(
                    label="Hostname",
                    placeholder="example.com",
                )

                forward_output = gr.JSON(
                    label="Forward lookup result"
                )

                forward_button = gr.Button(
                    "Forward lookup"
                )

                forward_button.click(
                    fn=ui_dns_forward,
                    inputs=hostname,
                    outputs=forward_output,
                )

            with gr.Column():

                ip_address = gr.Textbox(
                    label="IP address",
                    placeholder="127.0.0.1",
                )

                reverse_output = gr.JSON(
                    label="Reverse lookup result"
                )

                reverse_button = gr.Button(
                    "Reverse lookup"
                )

                reverse_button.click(
                    fn=ui_dns_reverse,
                    inputs=ip_address,
                    outputs=reverse_output,
                )


def _tab_port_scanner():
    with gr.Tab("Port Scanner"):

        gr.Markdown(
            PORT_SAFETY_MD
        )

        target = gr.Textbox(
            label="Target hostname or IP",
            placeholder="127.0.0.1",
        )

        ports = gr.Textbox(
            label="Ports",
            placeholder="80, 443, 8080",
            info="Comma-separated. Leave blank to use default ports.",
        )

        timeout = gr.Number(
            label="Per-port timeout in seconds",
            value=1.0,
        )

        authorized = gr.Checkbox(
            label=(
                "I confirm I own or have explicit permission "
                "to test this target"
            ),
            value=False,
        )

        output = gr.JSON(
            label="Scan result"
        )

        button = gr.Button(
            "Scan authorized target",
            variant="primary",
        )

        button.click(
            fn=ui_scan_ports,
            inputs=[
                target,
                ports,
                timeout,
                authorized,
            ],
            outputs=output,
        )


def _tab_http():
    with gr.Tab("HTTP Headers"):

        gr.Markdown(
            HTTP_SAFETY_MD
        )

        url = gr.Textbox(
            label="URL",
            placeholder="http://127.0.0.1:8000/",
        )

        timeout = gr.Number(
            label="Request timeout in seconds",
            value=10.0,
        )

        authorized = gr.Checkbox(
            label=(
                "I confirm I have permission to audit "
                "this non-local target"
            ),
            value=False,
        )

        output = gr.JSON(
            label="Header audit result"
        )

        button = gr.Button(
            "Audit headers",
            variant="primary",
        )

        button.click(
            fn=ui_audit_http,
            inputs=[
                url,
                authorized,
                timeout,
            ],
            outputs=output,
        )


def build_app():

    if not _GRADIO_AVAILABLE:
        raise RuntimeError(
            "Gradio is not installed. "
            "Install project dependencies first."
        )

    with gr.Blocks(
        title=TITLE
    ) as demo:

        gr.Markdown(
            f"# {TITLE}"
        )

        gr.Markdown(
            DISCLAIMER_MD
        )

        with gr.Tabs():

            _tab_base64()
            _tab_hash()
            _tab_password()
            _tab_dns()
            _tab_port_scanner()
            _tab_http()

    return demo


def main():

    demo = build_app()

    demo.launch(
        server_name="127.0.0.1",
        server_port=7860,
        share=False,
    )


if __name__ == "__main__":
    main()
