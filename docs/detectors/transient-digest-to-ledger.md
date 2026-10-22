# transient-digest-to-ledger

Availability: **opt-in**, no policy required. Severity/confidence: **low/high**.
Select with `--detectors transient-digest-to-ledger`.

The standard library documents that `transientHash` and `transientCommit` lack
upgrade stability and should not derive state data. This rule reports a terminal
modeled ledger operand constructed using either authenticated native primitive.
It groups each primitive source site and entry, listing affected writes and
invocations. It does not establish an actual upgrade failure, secrecy requirement,
concrete feasibility or vulnerability.

```compact
export ledger fingerprint: Field;
export circuit register(value: Field): [] {
  fingerprint = disclose(transientHash<Field>(value));
}
```

A fingerprint that must be recomputed after a compiler/protocol upgrade needs
a stable derivation. Use `persistentHash` or `persistentCommit` over stable inputs
when that is the required lifecycle. Changing an existing representation requires
an explicit migration. A persistent hash around a transient result still depends
on the transient algorithm. Intentional version-bound state, ephemeral caches and
compiler disclosure tests can match, so this compatibility review remains opt-in.

The origin annotation describes syntactic data derivation, independently of
private inputs. It survives modeled arithmetic, casts, helpers, snapshots and
aggregate construction; projecting another aggregate member does not inherit an
unrelated origin. Ambient control guards and arbitrary witness callback arguments
do not establish data derivation. Consistency-only assertions, return/event-only
outputs, namesake user functions, persistent-only derivations and definite final
overwrites stay quiet. Origins do not establish value equality or live storage.

Exact bounded observations are isolated from baseline analysis. Native hashes
and commitments, ordinary storage operands and Map keys/values are supported.
The observer disables compressed folds/hash choices and retains the original
40,000-step/256-path/50,000-value limits. Origins are limited to128 source sites;
the consumer shares200,000 applicability/lifetime/grouping checks. May-value
origins, wildcard/may-alias or partial overwrites, unsupported List/Merkle payload
lifetimes and exhaustion produce explicit rule/entry-scoped incomplete diagnostics.
Set removal after a transient-derived insertion is unavailable: whole-Set writes
do not expose enough element lifetime evidence. A final exact reset can discharge
an earlier uncertain operand. Other rules and baseline completion remain separate.
This does not track arbitrary TypeScript witness code or cross-entry upgrades.

Compiler acceptance and analyzer behavior are validated separately. The rule
does not establish application recall or an upstream defect.
