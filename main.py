"""
main.py
=======

Main entry point for the Personal Ethical Hacking Toolkit.

Run:

    python main.py

Local URL:

    http://127.0.0.1:7860
"""

from ui.web_app import (
    main as run_web_app,
)


def main():
    print(
        "Personal Ethical Hacking Toolkit"
    )

    print(
        "Starting local web interface:"
    )

    print(
        "http://127.0.0.1:7860"
    )

    print(
        "Press Ctrl+C to stop."
    )

    run_web_app()


if __name__ == "__main__":
    main()
