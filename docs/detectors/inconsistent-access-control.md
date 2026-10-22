# inconsistent-access-control

Availability: **opt-in** with `--detectors inconsistent-access-control`; no policy
required. Severity **medium**, confidence **low**. Explicit selection replaces the
default detector set.

This is an inferred code convention requiring review, not a claim of an exploitable
missing privilege check. Review the intended policy for each sibling entry; restore
a required check or document an intentional public exception.

The intended rule identifies a code convention: a strict majority of distinct
exported writers of the same declared ledger field, or callers of the same modeled
value-moving operation, require a caller-authentication relationship, while another
successful writer does not. No application policy or security meaning inferred from
names is sufficient. At least two guarded exported entries must support a majority;
repeated writes, helper calls and aliases of one entry cannot manufacture it.

Required evidence comes from actual successful predicates and ordered effects.
Only histories reaching the relevant effect enter its guard intersection. An ignored
comparison, rejected history, constant-only validation or same-named lookalike helper
cannot supply caller authentication. Private preimages constrained to public data
must not supply secret authentication, including constraints before hashing or after
the effect. Genuine alternate authentication must not be labeled an omission merely
because it uses a different helper, key or source kind. An atomic late guard may
constrain successful completion; its later position remains visible.

Constructor writes do not enter the exported-operation majority. Incomplete potential
writers prevent universal claims for their affected group. Unknown effects and
exhausted decoding/intersection budgets must remain explicitly incomplete, without
partial convention findings. Grouping writes to a declared collection is not proof
that different dynamic keys address the same cell.

## Supported evidence and limitations

An authentication convention is a required equality between a definite preexisting
ledger value and either a direct hash of one private input, or an exact raw witness
input. The hash may contain fixed aggregate prefixes or repetitions of that same
input. Witness and entry-parameter preimages support the same convention. Different
private inputs are not equated across entries: the shared key is the trusted ledger
origin, hash primitive and relationship kind. A raw equality is explicitly weaker;
it does not suppress an omitted secret-preimage convention.

The check intersects conventions across every successful reach of the target by
each exported entry. A strict majority, including at least two entries, must share
one convention. Another private-preimage check can satisfy the minority writer even
when its key or helper differs. Branch-local checks and ignored comparisons do not
become required checks. Whole-history public equalities, including aggregate
components and late assertions, disqualify a claimed secret preimage. Predicates
from mutually exclusive histories are never combined.

Targets are declared ledger fields or actual modeled transaction operations:
`mintShielded`, `mintUnshielded`, `claimZswapCoinSpend`,
`claimUnshieldedCoinSpend`, `createZswapInput` and `createZswapOutput`. Nested helper
names alone cannot establish these effects. Findings preserve the actual writer
invocation and sibling predicate call sites and effect positions. A collection
field groups its writers; it makes no must-alias claim about dynamic keys.

The bounded applicability walk only proves that a convention is impossible or
identifies potential incomplete writers. Dead syntactic writers do not enter the
majority denominator. The rule requires `predicateScope: "all-private"` exact
facts. Default and experimental Counter dispatch use whole-program inapplicability
to preserve existing correlated admission; a possible convention requires genuine
exact fallback. There is no per-entry no-witness certificate for this rule.
Applicability is bounded to 20,000 operations; predicate decoding/publicness and
intersection share a separate 1,000,000-operation allowance with bounded aggregate
expansion. Exhaustion returns diagnostics and no partial convention findings.

Signature/protocol validity, arbitrary transformed or multi-source preimages,
external caller trust and cross-transaction reachability are not proved. Authentication
through a relationship outside the documented patterns can look like an omission.
Two sibling operations using unrelated trusted ledger origins do not establish one
shared convention. Deliberately public reset, mint or transfer operations can match;
the compiler-valid intentional-public control explicitly expects that false-positive
shape. Review the access policy before adding a guard or suppressing the finding.

## Example and correction

```compact
import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger stored: Field;
witness secret(): Bytes<32>;
circuit caller(): [] {
  assert(persistentHash<Bytes<32>>(secret()) == owner, "owner");
}
export circuit first(next: Field): [] { caller(); stored = disclose(next); }
export circuit second(next: Field): [] { caller(); stored = disclose(next); }
export circuit missing(next: Field): [] { stored = disclose(next); }
```

`missing` is the minority writer. If it should follow the sibling policy, call
`caller()` before its write. If it is deliberately public, document that exception.
