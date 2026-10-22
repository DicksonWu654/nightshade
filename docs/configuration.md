# Nightshade configuration reference

Use [user-guide.md](user-guide.md) for runnable CLI/config examples, rule selection,
suppressions and the GitHub Action. The default config filename is `nightshade.json`;
`--config FILE` chooses an explicit JSON file.

| Field | Purpose |
|---|---|
| `version` | Required schema version: `1` |
| `roots`, `searchPaths` | Application roots and import directories, relative to config |
| `compilerVersion`, `zkirVersion` | Pinned semantic profile and ZKIR selection |
| `detectors` | Exact nonempty selection replacing defaults |
| `ruleIncomplete` | `error` (default) or `warn`; only rule-scoped gaps with complete baseline semantics may warn for CI |
| `failOn`, `minConfidence` | CI thresholds; findings remain visible |
| `minSeverity`, `exclude` | Output filtering and discovered-root exclusion |
| `budgets` | `maxSteps`, `maxPaths`, `maxValues` |
| `execution` | `timeoutMs`, `heapMiB`, `maxOutputBytes` |
| `policies` | Validated application intent; exact fields on per-rule pages |
| `suppressions` | Exact finding fingerprints with mandatory reasons |
| `experimentalCounterQueries` | Explicit experimental detector-predicate mode |

Unknown keys, wrong types and ambiguous policy selectors are errors. No compiler
executable path or detector module is loaded from config. Trusted host code can be
selected only through explicit CLI/API options. Diagnostics remain unsuppressible.

For compiler support, see [limitations](limitations.md). Report schema versions
are listed in [coverage](coverage.md), and rule availability is documented in
[detectors](detectors.md).
