## Description

<!-- What does this change do, and why. -->

## Related issue

<!-- Closes #123, or "None" if there isn't one. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / new detection signal
- [ ] Documentation only
- [ ] Refactor / internal cleanup (no behavior change)
- [ ] CI / packaging / tooling

## How was this tested?

<!--
Describe what you ran and what you observed. For a new detection signal,
say how you triggered it and what the report showed. For a bug fix, say
how you reproduced the bug before the fix.
-->

## Checklist

- [ ] `pytest` passes locally.
- [ ] `flake8 src/ main.py --count --show-source --statistics` is clean.
- [ ] `pylint --rcfile=.pylintrc --fail-under=9.5 src/ main.py` passes.
- [ ] New behavior has a test; a bug fix has a regression test.
- [ ] Docstrings/comments added for anything non-obvious.
- [ ] `CHANGELOG.md` updated, if this is user-visible.
- [ ] This PR targets `develop`, not `main` (unless it is a release/hotfix branch).
