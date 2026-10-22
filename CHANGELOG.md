# Changelog

## 0.1.1 — 2026-10-22

- Fixed scans becoming incomplete when the same contract or Nightshade installation
  is moved to a longer checkout path.
- Fixed report identifiers and review output filenames changing after moving a
  checkout.
- When upgrading from 0.1.0, regenerate baselines and suppressions for
  `secret-binding-divergence-review` and `membership-identity-binding-review`:
  their fingerprints changed so they stay stable when a checkout moves.
  Also regenerate `zero-amount-unguarded-map-debit-review` findings that use
  hashed keys. Report identifiers now stay stable when library callers preview
  entries or report them in a different order.
- Some scans that previously hit a resource limit on long checkout paths now
  finish and may report additional findings.
- Fixed finding fingerprints for filenames containing `$&`, `$'`, `$$`, or
  a dollar sign followed by a backtick; filenames are now treated literally.

## 0.1.0 — 2026-10-22

- Documented source, local tarball, Docker and GitHub Action installation, a
  shipped-example quickstart, configuration and suppression workflows, compiler
  profiles and per-rule review limits.
- Added Apache-2.0 distribution notices and package discovery metadata.
- Added bounded static analysis for Compact modules, calls, private-data flow and
  ledger effects, with source-mapped findings and explicit incomplete-analysis
  diagnostics.
- Added text, JSON and SARIF reporting, configurable detector selection,
  suppressions, offline review maps and GitHub Action support.
- Expanded compiler-profile handling, native input validation, collection and
  control-flow analysis, and UTF-8/UTF-16 source-map handling.
- Documented limitations for unsupported syntax, resource budgets, compiler
  profile differences and review-only findings.
