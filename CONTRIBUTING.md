# Contributing to Sys-Inspector

Thanks for taking the time to contribute. This document explains how to
report problems, propose changes, and get a pull request merged.

By participating, you agree to follow the project's
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Security vulnerabilities** are never reported as a public issue. See
  [SECURITY.md](SECURITY.md).
- **The "Sys-Inspector" name and logo are trademarked** (see
  [TRADEMARK.md](TRADEMARK.md)). The code is AGPL-3.0; the name and logo are
  not covered by that license.
- For a large or invasive change (new detection module, new capture mode,
  storage schema change), open an issue first to discuss the approach before
  writing code. It saves rework on both sides.

## Reporting a bug

Open a [bug report issue](../../issues/new/choose) and fill in the template.
Useful details: distribution and kernel version, the Sys-Inspector version
(`sys-inspector --version`), the run mode (`snapshot` / `daemon` / `server` /
`live`), the exact command, and the relevant log lines. If the issue is
security-sensitive (a false negative in detection, a way to evade a probe, a
crash triggered by untrusted input), use [SECURITY.md](SECURITY.md) instead.

## Suggesting a feature

Open a [feature request issue](../../issues/new/choose). Describe the
problem you are trying to solve before jumping to a specific solution; the
same underlying need sometimes has a simpler fix than the one first imagined.

## Development setup

Requires Python 3.6 or newer (the project supports Linux distributions that
ship older Python; avoid syntax that only exists in 3.8+).

```bash
git clone https://github.com/mariosergiosl/sys-inspector.git
cd sys-inspector
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pylint flake8 pytest cryptography
```

eBPF-based capture (`daemon` / `live` modes) needs BCC (`python3-bcc` /
`python3-bpfcc`, plus kernel headers matching the running kernel) and root
privileges. The `server` mode and the test suite do not need eBPF or root.

## Running the checks locally

These are the same checks the CI workflow (`.github/workflows/ci.yml`) runs
on every push and pull request:

```bash
pytest
flake8 src/ main.py --count --show-source --statistics
pylint --rcfile=.pylintrc --fail-under=9.5 src/ main.py
```

`process_tree.py` and anything that imports it depends on `pwd`/`grp`, which
only exist on Linux/macOS; on Windows, run those tests inside WSL or a Linux
VM.

## Code style

- Follow PEP 8. `flake8` and `pylint` (minimum score 9.5) must pass clean.
- Add a docstring to every new function and class.
- Keep compatibility with Python 3.6 in `src/` and `main.py`: no
  `dataclasses`, no walrus operator, and be careful with f-strings in code
  paths that also need to run on the oldest supported interpreter.
- New behavior needs a test. A bug fix should come with a regression test
  that fails before the fix and passes after it.
- Comments and docstrings explaining a non-obvious decision are welcome;
  prefer explaining *why* over restating *what* the code already says.

## Branching and commits

- `main` holds the latest stable release only.
- `develop` integrates finished work between releases.
- Branch from `develop` as `feature/<name>`, `fix/<name>`, or
  `release/<version>`, and open the pull request against `develop` (not
  `main`).
- Keep commits focused; a commit message should explain the reasoning behind
  a change, not just restate the diff.

## Pull requests

1. Make sure `pytest`, `flake8`, and `pylint` pass locally (see above).
2. Fill in the pull request template completely, including how you tested
   the change.
3. Keep the PR scoped to one topic; unrelated cleanups belong in their own PR.
4. A maintainer will review and may ask for changes before merging.

## License

By contributing, you agree that your contribution is licensed under the
project's [AGPL-3.0 license](LICENSE.md).
