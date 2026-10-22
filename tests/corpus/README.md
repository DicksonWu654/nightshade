# Security regression corpora

The corpus contains owned synthetic programs labeled for individual detectors.
Positive, corrected and intentional-lookalike examples preserve exact source-site
expectations in `manifest.json`, `known-bugs.json` and `synthetic-regressions.json`.
A negative example means quiet for the named detector; it does not establish that
the entire program is secure.

The synthetic triplet registry pins compiler versions, ZKIR versions, source hashes,
selected detectors, policies and positive/corrected/lookalike target lines. Empty
mappings and documented known gaps remain explicit; they are not successful
observations. These fixtures do not measure third-party security or production
precision.

`policies-manifest.json` contains explicit-policy examples. Policy labels describe
configured requirements, not independently inferred business intent. The feature
suite in `tests/fixtures/features` separately checks language and compiler behavior.

`COMPACTC_TEST=/path/to/compactc npm test` additionally validates compiler acceptance
using temporary directories and `--skip-zk`. Without that variable, compiler checks
are skipped explicitly. Passing analysis tests alone does not establish compiler
acceptance, successful execution, proof generation or exploitability.

Regression coverage includes branch isolation, failed assertions, lexical shadowing,
short-circuit expressions, tuple projection, module identity, import aliases,
transitive state effects, resource bounds, UTF-8 offsets, UTF-16 columns and reporting.
Unit-test snippets are not all compiler-validated corpus entries. Public upstream
library fixtures retain their licence notices and attribution.
