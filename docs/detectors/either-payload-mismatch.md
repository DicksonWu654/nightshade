# either-payload-mismatch

Availability: **default-on**; select only this rule with `--detectors either-payload-mismatch`; severity
**medium**, confidence **high**. Explicit selection replaces the default set.

The rule reports a canonical native Either arm selection when that receiver's
immutable `is_left` tag selects the other arm on a modeled successful history,
and the selected payload reaches a public output, a state/transaction effect,
an effect's actual control dependence, or a non-tautological assertion gating
an effect. It uses typed receiver snapshots, not common witness provenance.
Imported and nominal native aliases retain their identity; same-shaped user
structs are quiet.

## Example and scenario

```compact
export circuit gatedIncrement(allowed: Either<Field, Field>, claim: Field): [] {
  assert(!allowed.is_left, "right admission");
  assert(allowed.left == claim, "admission"); // validates the inactive arm
  round.increment(1);
}
```

Validate `allowed.right` after requiring the right tag. Both payload fields are
represented in Compact; projecting one does not itself constrain `is_left`.
The finding is an established tag/selection mismatch with a modeled consequence,
not a proof of an authorization bypass or deployed exploit.

## Recommendation and limits

Check the same receiver's tag and use its selected payload. An assertion after
an effect can still constrain successful completion because effects are atomic.
A tag check on replacement ledger storage cannot repair a retained old snapshot.
Independent dynamic Map lookups do not share a definite tag merely because their
regions may alias. Helpers, destructuring, aggregate payloads and aliases use the
same observation transfer.

Bare unused reads, unknown tags, same-shaped application structs, tautological
assertions, identical total/effect-free conditional arms, and branches that neither reject nor control an effect stay quiet.
A direct untransformed arm copied into an explicit native Either construction
establishes a new receiver choice; that copy alone is exempt. Subsequent selection
uses the new receiver's tag. Computations over the original arm preserve their
dependencies. General variant lifecycle/protocol validation, branch-rejection
proofs for effects after joins, unconstrained witness-output dependence, and
correlated may-history certificates are outside this rule.

## Evidence and known false positives

Branch-expanding entries first try a `conservative-absence` certificate (see
docs/coverage.md): a complete conservative may-view in which every native Either
payload selection reads the arm selected by its receiver tag, refined to that
constant by the joined current constraints. Any unknown or inactive tag is a
candidate and falls back to exact observation with the remaining allowance.

Observation shares the configured work/value allowances, retains at most 256
reads per history, 4,096 Boolean/control observations, conditional chains of
at most 64 observations, and limits consequence traversal to 200,000 work units.
`either-evidence-budget`, `either-finding-budget`, or missing exact evidence
produce an explicit incomplete diagnostic. Incomplete roots supply no negative
coverage claim. Instruction/reference and requested-cache/uncached tests cover
these semantics; cached requests currently use the uncached transfer.
