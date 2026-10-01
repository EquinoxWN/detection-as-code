# ADR 0002: Test rules with a local evaluator first, a real SIEM second

- **Status:** Accepted

## Context

The goal is that every rule fires on attack logs and stays quiet on benign logs, checked in CI.
The full design loads logs into Elastic in Docker and runs the pySigma-converted queries (M2).
That needs a multi-gigabyte container, a minute of start-up per CI run, and Docker on the
developer's machine. M1 needs a fast loop that works anywhere.

## Decision

- M1 ships a small, strict Sigma evaluator (`sigma.py`) that replays JSON events in milliseconds.
  It implements only what the rules use (field modifiers `contains`, `startswith`, `endswith`,
  `all`, `re`, wildcards, and boolean and `1 of` / `all of` conditions) and raises
  `UnsupportedSigmaError` for anything else, so it can never silently mis-evaluate a rule.
- Every rule is also parsed by the official pySigma library in CI, so the rules stay valid Sigma
  for any backend.
- M2 adds the Elastic-in-Docker job, which runs the same fixtures through the real backend query.

## Consequences

- The local test loop takes under a second and needs no Docker.
- A rule that uses a feature the evaluator lacks fails loudly until support and tests are added.
- There is a small risk that the local evaluator and Elastic disagree. The M2 job exists to catch
  exactly that, and any disagreement becomes a regression test here.
