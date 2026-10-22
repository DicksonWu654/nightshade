# ADR 0021: bounded List prefixes and qualified outcomes

Date: 2026-09-26. Status: implemented.
[ADR 0023](0023-list-nonempty-refinement.md) subsequently extends this original
prefix contract with revision-checked nonempty-tail refinement.

## Context

The common ledger catalogue treated List operations conservatively and incorrectly
accepted `size()`. Compact 0.34.0 uses `length()`. Typed signatures alone did not
retain order, payload snapshots or distinguish structural dependencies from values
stored in the List. Treating every query as a function of all pushed payloads
also introduced unnecessary privacy dependencies.

The matching runtime 0.19.0 qualifies push-front order, known nonempty pop, empty
defaults/reset and Maybe head values in owned fixtures. An empty pop evaluates
successfully there, while subsequent combined inspection rejects; reset restores
the representation. Neither an immediate-abort rule nor a no-op rule is justified.
These are circuit-evaluation observations, not transaction-validity evidence.

## Decision

Track a finite ordered prefix over an empty or unknown suffix in reusable
`ListFacts`, separate from Map/Set membership. External entry state is unknown;
constructors, resets and inserted defaults can establish empty state. Push extends
the known prefix. Pop removes only a known prefix cell. Head/length/isEmpty use
the facts that are known, leaving an unknown suffix unknown.

Store payload and structural provenance separately. Unconditional insertion of a
private payload does not make its contents a dependency of length or emptiness.
Conditional changes and region selection remain structural dependencies. Every
cell retains the prior structure, and pop preserves control accumulated through
later structural changes. Even the default value of an absent head retains the
dependencies that selected that representation.

Saved payloads recursively detach live storage regions while retaining value
identity, fields, items and dependency evidence. Later writes cannot turn a saved
aggregate into a live ledger projection. Query results are snapshots; revisioned
identities never treat wildcard paths as must-equal values.

The domain bounds tracked List regions and total prefix cells to 256 each. It
copies containers on clone/snapshot and treats payloads as immutable. Ancestor and
wildcard writes forget affected facts. Exhaustion is sticky and reports
`list-budget`; recursive saved payloads also consume the ordinary abstract-value
budget. Unsupported empty/possibly empty pop reports
`list-pop-outcome-unqualified`, leaves the entry incomplete and does not invent
an assertion failure. A later reset cannot erase that diagnostic.

Both engines and mutation-summary replay use the same ledger transfer. State
identity, read-summary footprints and retained-value liveness include List facts.
Read summaries therefore cannot reuse stale order or discard constraints needed by
retained payloads. The existing summary entry/event/value limits remain in force.

## Validation and limits

Domain tests compare concrete stack sequences and exercise unknown suffixes,
container isolation, structure restoration, overlap invalidation and budgets.
Compiler-grounded integrations compare both engines with caches on/off, requiring
real read and mutation cache hits where reuse is claimed. They cover snapshots,
nominal/aggregate values, nested defaults, wildcard replacement, provenance,
guard invalidation, correlated branch histories and explicit incomplete outcomes.
Packed consumers check ordered values and unsupported-pop reporting.

The bounded prefix is not general List algebra. In particular, observing a Boolean
nonempty predicate does not recover an unknown head cell, and unknown-tail pop
remains incomplete. No coin/tree/Kernel model, transaction reachability, general
correlated join or branching summary follows from this domain. Independent review
and broader release/platform/performance gates remain separate requirements.
