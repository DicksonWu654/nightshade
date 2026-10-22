# resettable-list-nonce

Availability: opt-in. Severity: low. Confidence: high.

Whole-root or identical literal selectors establish the same storage region.
Dynamic Map selectors establish only may-overlap: the finding does not equate
independent wildcard reads or assert that callers choose equal selectors.
The review identifies a source that cannot serve as a monotonic extent across
potential resets. Transaction feasibility, actual nonce recurrence, authorization
intent, secret compromise and cryptographic attacks remain unproved.

The consumer uses immutable query and native invocation snapshots, never variable
names or a union of ledger dependencies. Caller nonce inputs, independent Counters,
length used only as an amount, distinct literal selectors, aborted resets and local
namesake helpers do not establish this relationship. Generic arithmetic, unknown
seeds, decreasing pop operations and arbitrary crypto consumers are outside this
initial contract.

The informational companion [`resettable-memo-nonce-review`](resettable-memo-nonce-review.md)
adds a separate, narrower paired consumer observation for an exact selected
recipient List and direct evolved payload append. It preserves this coin rule's
findings and does not infer the stored payload's cryptographic role. Coin-only
quiet controls do not establish memo uniqueness.
