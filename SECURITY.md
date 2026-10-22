# Security and reporting

Nightshade is a static analyzer, not a security guarantee. It does not prove
path feasibility or contract safety. Incomplete analysis is never a clean result.

Normal scans do not use the network, load executable configuration or plugins,
run witness callbacks, or execute contracts. Explicit `--detector-module` and
API `detectorModules` options execute trusted local JavaScript with host
permissions. The explicit `--compiler` option executes the selected compiler binary. Dependency installation and release
qualification use separate tools.

Run analysis on untrusted repositories in an OS or container sandbox with
process memory and time limits. Internal analysis budgets are not a complete
isolation boundary, particularly for native parsing and external compilers.

Report security issues through the repository's
[Report a vulnerability](https://github.com/DicksonWu654/nightshade/security/advisories/new)
form using GitHub private vulnerability reporting. Include the analyzer version,
compiler profile, relevant diagnostics, and a minimal synthetic example when
possible. Do not send credentials, witness secrets, or private application source
without an agreed secure channel. Do not publish unpatched application findings;
coordinate disclosure with the affected project owner.
