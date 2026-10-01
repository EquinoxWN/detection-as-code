# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/detection-as-code/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** Evaluator bugs that make a rule miss an attack event or match silently wrong, and unsafe parsing of rule or log files.
- **Out of scope:** Requests for new rules (open an issue instead). Never submit live malware, real credentials or real customer logs: fixtures must stay inert text.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot proposes dependency and action updates weekly as reviewable pull requests.
- CI runs lint, tests and a known-vulnerability audit (`make audit`) on every push and pull request.
