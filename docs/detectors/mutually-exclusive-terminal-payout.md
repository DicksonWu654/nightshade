# mutually-exclusive-terminal-payout

Availability: **opt-in state-machine/effect review**, no policy required. Severity/confidence: **high/medium**.

The rule finds a sibling one-time milestone transition (a represented Boolean
false-to-true write) and a timeout/refund/release-style exported circuit that
performs a canonical token payout and terminal-state write without reading the
milestone state. It recognizes standard-library send lowering and reports the
user call site. This is a cross-entry continuation review: censorship assumptions,
commercial policy and runtime asset custody remain unproved.

An application may intentionally allow the payout independently of a sibling
milestone, or may use the state solely for off-chain coordination; either can
produce a valid review match. The rule compares source-level entry effects. It
does not prove transaction ordering, simultaneous reachability, custody loss, or
that the milestone is the application's intended completion condition.
