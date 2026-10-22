# Caller-supplied time review

Availability: **opt-in** with `--detectors caller-supplied-time-review`; no policy
required. Severity/confidence: **medium/low**.

On a local exported-circuit branch with a ledger write or canonical send, flags an
enforced comparison that places a caller `Uint<64>` above a ledger-derived bound
without enforcing `blockTimeGte` or `blockTimeGt` on the same value. A `Uint<64>`
need not represent time; independent review must establish that intent.

Uses resolved identities, local aliases and separate branch states. It does not
infer time from names, comments or strings. Direct calls are supported;
helper-mediated constraints are outside this review. Unsupported loops and
exhausted traversal budgets produce diagnostics.

A caller-supplied numeric bound can be intentional, and the rule does not infer
that the value represents a timestamp. Review the protocol's time source and
same-branch guards before changing the circuit; this finding does not prove a
feasible stale-time execution.
