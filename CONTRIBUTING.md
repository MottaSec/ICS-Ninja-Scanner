# Contributing to ICS Ninja Scanner

Thanks for your interest in making ICS security better. Here's how to get involved.

## Dev Environment Setup

```bash
# Clone and enter the repo
git clone https://github.com/mottasec/ics-ninja-scanner.git
cd ics-ninja-scanner

# Create a virtualenv
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install everything — all protocol libs + dev tools
pip install -e ".[all,dev]"
```

You now have `ics-ninja` on your PATH, plus `ruff`, `pytest`, and `mypy`.

## Adding a New Protocol Scanner

This is the most common contribution. Here's the step-by-step:

### 1. Create the scanner file

```bash
touch scanners/new_protocol_scanner.py
```

### 2. Inherit from BaseScanner

```python
"""New Protocol scanner for ICS Ninja Scanner."""

from scanners.base_scanner import BaseScanner


class NewProtocolScanner(BaseScanner):
    def __init__(self):
        super().__init__(
            name="New Protocol",
            default_port=12345,
            description="Brief description of the protocol"
        )

    def scan(self, target, port, intensity, timeout):
        """Run security checks against the target."""
        results = []

        # Low intensity — passive checks only
        results.extend(self._check_connectivity(target, port, timeout))
        results.extend(self._check_version(target, port, timeout))

        if intensity >= 2:  # Medium
            results.extend(self._check_authentication(target, port, timeout))
            results.extend(self._check_encryption(target, port, timeout))

        if intensity >= 3:  # High
            results.extend(self._check_write_access(target, port, timeout))

        return results
```

### 3. Register it

Add your scanner to `scanners/__init__.py`:

```python
from scanners.new_protocol_scanner import NewProtocolScanner

SCANNERS["new_protocol"] = NewProtocolScanner
```

### 4. Add tests

Create `test/scanners/test_new_protocol_scanner.py` with tests that mock network calls. See existing scanner tests for examples. Every scanner test should cover:

- Scanner initialization
- Behavior when target is unreachable
- Each intensity level
- Proper error handling

### 5. Update optional dependencies

If your scanner needs a third-party library, add it to `pyproject.toml` under `[project.optional-dependencies]` and to the `all` group.

## Scanner Quality Checklist

Before submitting a scanner PR, make sure it meets these standards:

- [ ] **3 intensity levels** — low (passive), medium (queries), high (write/control tests)
- [ ] **5+ security checks** — authentication, encryption, access control, version info, config issues
- [ ] **Safe by default** — no writes or state changes at low/medium intensity
- [ ] **Graceful dependency handling** — works (with reduced functionality) if optional lib is missing
- [ ] **Proper error handling** — timeouts, connection refused, unexpected responses all handled
- [ ] **Rate limit aware** — respects `--rate-limit` for fragile ICS devices
- [ ] **Docstrings** — module, class, and public method docstrings
- [ ] **Tests pass** — all existing + new tests green

## Code Style

We use [ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
# Check for issues
ruff check .

# Auto-fix what's fixable
ruff check --fix .

# Check formatting
ruff format --check .

# Auto-format
ruff format .
```

Rules: 120 char line length, Python 3.10+ target. We enforce `E`, `F`, `W`, and `I` (isort) rules.

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=scanners --cov=utils --cov-report=term-missing

# Run a specific test file
pytest test/scanners/test_mqtt_scanner.py

# Run a specific test
pytest test/scanners/test_mqtt_scanner.py::TestMQTTScanner::test_scan
```

All tests must pass before merging. We mock network calls — no real ICS devices needed.

## PR Process

1. **Fork** the repo
2. **Branch** from `main` — use `feat/protocol-name` or `fix/description`
3. **Write code** following the style guide and scanner checklist
4. **Test** — run the full suite, add tests for new code
5. **PR** — describe what you did and why. Link any related issues.

We review PRs within a few days. Be ready for feedback — ICS security tools need to be rock solid.

## Questions?

Open a discussion on GitHub or email info@mottasec.com. We don't bite.
