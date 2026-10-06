# Personal Ethical Hacking Toolkit

A modular Python cybersecurity learning toolkit built as a college semester project.

The project demonstrates several common security and networking concepts through small, readable Python modules and a local Gradio web interface. It also emphasizes automated testing, input validation, and responsible authorized use.

---

## Educational / Authorized-Use Disclaimer

This toolkit is intended only for:

- learning and coursework
- systems you personally own
- systems you have explicit permission to test

Port scanning is an active network operation. Do not scan systems without authorization.

The HTTP security-header auditor sends a request to the target and should also only be used on systems you are authorized to test.

Results produced by this project are educational observations and should not automatically be interpreted as proof that a system is vulnerable.

---

## Features

- Base64 encoder / decoder
- Hash generator
- Password strength checker
- DNS forward / reverse lookup
- Authorized TCP port scanner
- HTTP security-header auditor
- Gradio web interface

### Base64

Base64 is encoding, not encryption.

### Hashing

Supported algorithms:

- SHA-256
- SHA-512
- SHA-1
- MD5

MD5 and SHA-1 are included only for historical and educational comparison.

### Password Strength

The password checker uses transparent rule-based scoring and does not prove that a password is secure.

### Port Scanner

The scanner requires explicit authorization and is limited to simple TCP connection checks.

### HTTP Header Auditor

The auditor checks a single URL for common security headers. Missing headers are configuration observations, not automatic proof of vulnerability.

---

## Requirements

- Python 3.10 or newer
- Gradio
- pytest

This project was developed and tested using Python 3.13.

---

## Installation

Create a virtual environment:

    python -m venv .venv

Activate it in PowerShell:

    .\.venv\Scripts\Activate.ps1

Install dependencies:

    python -m pip install -r requirements.txt

---

## Run the Application

    python main.py

Then open:

    http://127.0.0.1:7860

The Gradio app binds to 127.0.0.1 and uses share=False.

---

## Run Tests

Run all tests:

    python -m pytest

Run one test file:

    python -m pytest tests\test_port_scanner.py -v

Run one test:

    python -m pytest tests\test_port_scanner.py::test_authorization_required -v

---

## Local HTTP Demo

Start a local server:

    python -m http.server 8000

Then audit:

    http://127.0.0.1:8000/

---

## Technologies Used

- Python
- Python standard library
- Gradio
- pytest
- unittest.mock

---

## Project Purpose

The goal is to demonstrate how cybersecurity utilities can be implemented safely, tested automatically, organized into reusable modules, and presented through a simple local web interface.
