# Personal Ethical Hacking Toolkit

## Project Summary

### Project Objective

The objective of this project is to design and implement a modular Python toolkit that demonstrates foundational cybersecurity and networking concepts while emphasizing responsible, authorized use.

The application combines independent Python modules with a Gradio web interface and an automated pytest test suite.

### Problem Being Addressed

Cybersecurity students often use mature tools without seeing how the underlying concepts work. This project implements smaller educational versions of common utilities so that the program logic remains readable and understandable.

### Architecture Overview

The project uses a layered architecture:

- modules: core feature implementations
- config.py: shared configuration
- ui/web_app.py: Gradio presentation layer
- main.py: application entry point
- tests: automated pytest suite

### Module Overview

- base64_util.py: Base64 encode and decode
- hash_gen.py: SHA-256, SHA-512, SHA-1, and MD5 hashing
- password_strength.py: rule-based password scoring
- dns_lookup.py: forward and reverse DNS lookup
- port_scanner.py: authorized sequential TCP connect scanner
- http_headers.py: single-URL HTTP security-header auditor
- web_app.py: Gradio UI

### Safety and Ethical Design

The project includes explicit safety controls:

- port scanning requires authorization=True
- the Gradio UI includes authorization checkboxes
- non-local HTTP auditing requires authorization
- no exploitation is implemented
- no stealth or evasion is implemented
- no credential attacks are implemented
- the web interface is local only
- passwords are not intentionally logged or stored

### Testing Approach

The project uses pytest and unittest.mock.

Testing covers:

- valid inputs
- invalid inputs
- edge cases
- authorization behavior
- DNS failures
- socket errors
- HTTP failures
- password privacy
- UI wrapper behavior
- Gradio application construction

Network behavior is mocked during automated testing so tests do not depend on third-party systems.

### Important Implementation Decisions

- one feature per module
- standard-library core functionality
- structured return dictionaries
- transparent password scoring
- strict Boolean authorization checks
- disabled HTTP redirect following

### What Was Learned

This project provided experience with modular Python design, input validation, sockets, DNS resolution, HTTP requests, hashing, Base64, automated testing, mocking, Gradio, and responsible security-tool design.

### Possible Future Improvements

- UI accessibility improvements
- user-controlled result export
- additional edge-case tests
- coverage reporting
- installable Python packaging
- Docker-based development

### Conclusion

The Personal Ethical Hacking Toolkit demonstrates how cybersecurity utilities can be modular, understandable, testable, and safety-conscious.
