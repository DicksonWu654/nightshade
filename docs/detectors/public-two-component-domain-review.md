# public-two-component-domain-review

Availability: **opt-in**, no policy required. Severity: **info**. Confidence: **high**
for the stated source relationship.

Select with `--detectors public-two-component-domain-review`.

This review observes a public ledger write containing a canonical native
`persistentHash` of exactly two distinct scalar entry parameters of type
`Bytes<32>`. The represented preimage lacks a canonical `kernel.self()` value,
and assigning both components their default bytes is compatible with supported
component-only scalar equality guards on a modeled successful history. Findings
identify the actual native hash span, the two parameter declarations and the
public write. An authorization consumer is unnecessary.

The scope deliberately excludes a history when either component's default is
excluded by a required supported equality guard. Thus both `salt != default`
and `owner != default` can be quiet, independently of self binding. This is a
narrower source surface, not a general repair of an owner/salt domain obligation:
an owner restriction may still admit default salt, and nonzero salt alone does
not establish uniqueness or instance separation. Late checks constrain complete
successful histories. Exclusive branches retain separate guards.

Canonical self must reach the actual preimage. A helper-returned self value or
its exact bytes projection qualifies; storing self separately does not. A known
single-component identifier, a single aggregate parameter, constant component,
repeated parameter or other fully represented shape is outside the two-scalar
scope. Other native hash/commitment primitives are outside this initial rule.
Opaque or transformed preimages, opaque component guard operands, missing exact
history evidence and exhausted preparation/proof budgets yield rule-scoped
incomplete diagnostics. Absence of a rejection check alone never supplies a
feasible-default claim. Baseline-incomplete entries withhold structural absence;
standalone preparation also requires a complete resolved callable closure.

Preparation, exact interpretation, traversal and retained certificates share the
existing limits: 40,000 steps per entry, 256 paths and 50,000 cumulative abstract
values. Instruction/reference and cached/uncached execution preserve the same
findings. Values measure cumulative abstract allocation units, not physical
memory. The ordinary scan remains independent of this opt-in observation pass.
