# zero-default-getter-membership-review

Availability: **opt-in**, no policy required. Severity: **info**. Confidence:
**high** for the supported static source relationship.

Select with `--detectors zero-default-getter-membership-review`.

`zero-default-getter-membership-review` is an opt-in informational source
review. It infers neither token-standard semantics nor application policy.
The existing `zero-amount-initial-membership` rule continues to require an
explicit policy and retains its independent evidence.

Admission requires a completed exported numeric getter whose exact histories
return the immutable numeric Map lookup when present and explicit numeric zero
for absence at every prefix of that lookup chain. Getter histories may not
write storage or require unrelated gates. Within the getter, every membership
query uses the actual raw parameter or constant operands of the returned
lookup; matching types and parameter names do not supply equality.

The corresponding spender's ordinary decrement operands select a directly
bound exported numeric amount. With only that amount fixed to zero, every full
successful history must decrement the same immutable lookup into its exact Map
cell and require that cell initially. Ordered mutation/revision proof excludes
supplied membership and uncertain origins. A successful zero bypass withholds
the finding; a qualified explicit rejection is a quiet control, with no claim
of successful zero execution.

Cross-entry correspondence uses canonical ledger declaration identity plus
ordered literal/raw-parameter key patterns. Parameter roles are alpha-renamed
only for this cross-entry comparison, retaining types and repeated-use roles.
The finding exposes the original parameter correspondence and does not claim
that values from separate transactions are equal. Derived/aggregate operands
and wildcard selectors do not qualify.

Analysis is isolated from baseline facts, uses exact all-predicate histories,
and keeps the existing 40,000-step / 256-path / 50,000-value defaults. This
cross-entry pass shares its work/value allowance across relevant entries and
admits at most 64 exported entries. An incomplete relevant entry withholds the
whole relation and produces rule diagnostics. Ordinary baseline diagnostics
and unrelated rules remain independent.

Preparation, key roles/selectors, paths, prefixes, absence maps, certificates,
helper snapshots and orchestration references consume the shared work/value
allowance. Values count cumulative allocations; serialized text uses bounded
64-code-unit chunks and a conservative JSON-escaping reserve. Tight preparation
or proof retention budgets produce incomplete coverage before unqualified
evidence can be returned. Missing resolved callable/source closure also blocks
structural absence. Reporting diagnostics remain available on exhaustion.

Finding `initialRequirements` contains only exact raw cell keys along the
selected lookup's prefix chain. Additional same-root requirements remain
invocation gates and do not appear as supporting selected-chain evidence.

Incomplete and rejected inputs provide no absence guarantee. The observer's raw
scalar/constant key scope remains explicit above.
