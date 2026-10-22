# caller-supplied-ledger-equality

Availability: **opt-in review**, no policy required. Severity/confidence:
**medium/high**. Select with `--detectors caller-supplied-ledger-equality`.

An unchanged caller-supplied `Bytes<32>` leaf must equal definite preexisting public
ledger bytes before every modeled successful reach of an affected write or Kernel
effect. The finding groups one guard site per entry and lists the actual effects,
invocations and immutable ledger identities. Neither `disclose` nor this equality
establishes secret possession. The input may remain private to the caller.

```compact
import CompactStandardLibrary;
export ledger admin: Bytes<32>;
export ledger paused: Boolean;
export circuit pause(caller: Bytes<32>): [] {
  assert(disclose(caller) == admin, "claimed admin");
  paused = true;
}
```

If this argument represents caller authority, separately enforce the protocol's
reviewed signature or secret-possession relationship, bound to the intended key,
message and replay domain. A supported enforced private-preimage check against
preexisting ledger data on every reaching history suppresses this review; that
check still relies on secrecy and adequate entropy. Additional arbitrary checks
remain visible in the histories and prevent any sole-authorization inference.
Later publication is a separate disclosure-analysis obligation; a suppressed
review does not establish that a preimage remains secret throughout a protocol.

Known review noise includes routing, public record consistency and mock identity
checks. These legitimate patterns make the rule opt-in. A source-correct match
is not a confirmed authentication defect, a concrete path or a deployed bypass.

Constructor setup, optional/discarded/negative/after-effect comparisons, transformed
inputs and self-written ledger echoes do not meet this contract. Old snapshots
retain their initial revision. Scalars other than `Bytes<32>`, dynamic membership,
general multi-secret/signature proofs and cross-entry protocol intent remain outside.

The isolated exact pass observes all successful predicates, disables compressed
fold/hash histories and retains the ordinary 40,000-step/256-path/50,000-value
limits. It never reuses witness-only source-query certificates to prove this new
obligation. Baseline-incomplete entries, wildcard selectors, missing predicate or
invocation identities and exhausted evidence produce rule/entry-scoped incomplete
diagnostics, separately from baseline completion. Consumer work is bounded to
200,000 applicability/decomposition/intersection checks.

Constant-refined root inputs retain their unchanged identity. Conversely, a
potential alternate preimage check with reconstructed/transformed equality
dependencies cannot establish private status: bytewise equality may expose a
whole preimage without equating its original scalar identity. Such entries are
explicitly rule-incomplete; this consumer does not prove reconstruction secrecy.
