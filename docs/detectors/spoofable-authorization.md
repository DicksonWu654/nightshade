# spoofable-authorization

This default detector reviews exported circuits where a prover-supplied witness
is required to equal a constant or public ledger value before a state-changing
effect. Such an equality proves that the supplied value matches public data; it
does not prove possession of a secret. Public-data validation can be intentional
and still produce a finding.

The detector follows required conditions across successful paths and groups
affected effects by guard source and circuit. It preserves operand identity,
branch polarity, call site, storage revision, and the guard's position relative
to effects. A comparison that is computed but not enforced does not qualify.
Identity-preserving copies and casts remain raw witness values; hashing a private
preimage is a different relationship.

Severity and confidence describe the structural evidence, not a conclusion about
application intent. A sole modeled raw-witness or constant gate on a privileged
effect can receive critical severity. Other privileged witness checks and public
ledger key equalities receive high priority. Setup and nonprivileged validation
remain low priority. A canonical receipt-coordination effect alone is classified
as low-priority receipt validation; other affected effects in a mixed group are
assessed separately. Circuit, ledger, and witness names are labeled heuristics,
not proof of privilege or authentication intent. Signature-like witness names
can raise review priority but cannot establish signature verification or support
critical severity.

For example, checking `identity() == owner` before changing state establishes
only equality with the public `owner` value. If the protocol requires secret-key
authorization, it should constrain a private preimage to trusted, preexisting
owner data using the protocol's reviewed authentication construction. Review
initialization, key handling, replay protection, and disclosure independently.

Critical grading is deliberately conservative: every enforced condition must be
a definite constant or a fully classified raw-witness comparison with public
data. Additional private inputs, ledger conditions, ranges, collection
predicates, checked conversions, arithmetic, lookups, or derived transaction
operations prevent sole-gate certification. This test is sufficient evidence
for a structural grade, not a general authentication proof.

Private-preimage checks suppress the raw-equality finding only when they are
required on every successful reach and bind the exact private input to trusted,
preexisting ledger data. Self-written hashes, unrelated inputs, possible
may-alias values, or a check present on only some paths do not establish that
relationship. Public constraints on the preimage, entropy, later disclosure,
and arbitrary signature or protocol authentication are outside the detector's
proof.

Unsupported rollback behavior and exhausted traversal or value budgets produce
incomplete diagnostics; incomplete analysis does not establish absence of a
finding. Aggregate conditions must be fully classified. Receipt-only findings
describe receipt coordination and do not establish whole-transaction validity.
