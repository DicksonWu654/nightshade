# Inconsistent keyed-state guard

Availability: **opt-in** with `--detectors inconsistent-keyed-state-guard`.
Severity: **info**. Confidence: **high** for the structural observation.
No policy required.

The rule reports a final keyed insertion reached by some successful histories
with a prerequisite membership check and others without it. A downstream entry
must require both collections to contain the same exact key on every modeled
successful history. Collection identity comes from resolved ledger declarations;
collection names and assertion messages do not affect matching.

This is a review obligation. Consumer checks do not prove that surplus entries
are invalid. Intentional preauthorization or independent storage may explain the
pattern. Findings leave invariant intent, cross-transaction feasibility and
exploitability unproven. Confirm the application's intended relationship before
requiring membership on every successful insertion.

Analysis schedules one shared pass of exact successful histories, all predicates
and ordered collection observations, including helper calls and cached transfers.
Whole entries form dependency components through every canonical ledger root they
may read or write, including ordinary key, control and value dependencies. Resolved
source bodies, helper closures and zero-iteration callbacks participate. Every
entry in a component containing Map/Set membership or insertion is included, even
when that entry only removes an element or reads ordinary state.
Unchanged assertions after an insertion still constrain its atomic success.
Only unchanged, preexisting revision-zero prerequisite receivers are supported.
Any prerequisite-root mutation or later target-root mutation prevents a finding.
Map lookup alone does not establish the consumer relationship in this version.
Unknown required keys, unsupported Boolean relations, incomplete histories or
exhausted budgets produce diagnostics. These gaps never establish a clean rule
result. A resolved absence of reachable Map/Set membership and insertion establishes
not-applicable coverage without a dedicated collection-history observation pass.
Resolved callback and helper edges participate in this bounded certificate.
Unknown callable bodies, unknown external-contract effect scope or unfinished
dependency traversal prevent all disjointness certificates and diagnose. Excluded
entries and component dependencies are revalidated before relation analysis;
Program.entries is never changed.
Preparation and detector traversal work appear in ruleObservationWork metrics and
consume the shared observation work/value allowance. Complete relevant histories
remain required for every entry in the related component. A completed component
can report beside an incomplete disjoint component. Unrelated branches inside a
writer still make that whole entry incomplete; partial histories are never sliced
into completed relation evidence. Shared work/value exhaustion can withhold proof
even for previously completed histories. The independent baseline scan and overall
report still retain their analysis gaps. Unscoped engine issues are conservatively
associated with all incomplete components; these scopes do not identify an exact
failure origin.
