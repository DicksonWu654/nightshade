# native-key-authentication-review

Availability: opt-in. Severity: info. Confidence: high.

Opt-in candidate, informational severity and high confidence in the static source relationship. Canonical native `ownPublicKey` is prover supplied and does not separately establish control of the corresponding key. The rule observes a required exact equality to preexisting ledger data on completed successful effect histories, either with an independent mandatory private-preimage check or with the native key as an exact ingredient of a canonical hash/commit credential containing another private witness input.

Other secret credentials can provide sufficient authentication. Legitimate intentional constructions can match. This observation establishes neither authentication intent, transaction feasibility, separate key control nor an authentication bypass. Direct raw native-key cases lacking a mandatory secret-preimage check remain covered by `spoofable-authorization`.

Matching uses canonical native source identity and exact immutable input snapshots, never witness names or dependency unions. Optional/disjunctive checks, preview-only comparisons, unrelated key/secret predicates, self-written ledger credentials and wildcard selectors do not establish the required relationship. Unknown predicate/invocation evidence and exhausted observation allowances produce rule-scoped incompleteness. The closed terminal Counter grammar certifies absence because it excludes all witnesses.

Commitment input/randomness snapshots use a dedicated observer flag. Ordinary
digest observation supplies no commitment-evidence certificate; selecting this
review enables it in the isolated rule pass. Missing applicable snapshots remain
rule-scoped incomplete.
