# low-entropy-hash-disclosure

Availability: **default-on**; select only this rule with `--detectors low-entropy-hash-disclosure`;
severity **medium**, confidence **high**. Explicit selection replaces defaults.

The rule reports an exact published native digest with one direct private source
whose selected private leaf type has at most **65,536** values. Boolean, small Uint, Bytes and
enum domains (including nominal aliases) are supported. Public ledger context does
not add secret uncertainty. The bound is a type-domain upper bound, not an entropy
estimate, a secrecy policy or proof that an application has a vulnerability.

## Example and scenario

```compact
export circuit recordVote(vote: Boolean): [] {
  voteDigest = disclose(persistentHash<Boolean>(vote));
}
```

A digest of a Boolean is drawn from a two-candidate input domain. Hashing alone
supplies no useful hiding for this vote when its digest is published. A protocol
that intends to keep votes hidden should use a suitable commitment with
sufficiently unpredictable private opening randomness, then reveal it only at
the intended phase. The pinned standard-library documentation explicitly requires
acknowledged disclosure for hashes and distinguishes commitments with random
openings; `disclose` itself is permission, not secrecy protection.

Publishing a low-domain digest can be intentional when the input is already public
or the protocol explicitly accepts that disclosure. Review the actual privacy
requirement; a match is a domain-size warning, not proof that a secret or exploitable
value has been exposed.

## Evidence and limitations

Immutable typed native digest inputs follow aliases, helpers and aggregate copies
to public sinks. Projected fields retain their leaf type. A raw input published
on the same successful history is public context, including later atomic writes;
publishing a transformed salt does not establish publication of its preimage. A hash comparison or hash-dependent branch is not publication of
the digest. Private-salted/multiple-private-source hashes, arbitrary transformed
inputs, commitments and domains above the threshold stay outside this rule's
scope. There is no claim of general entropy analysis or multi-secret guessing.
An exported return is an application-output boundary, not necessarily a globally
public ledger. Raw witness and entry-parameter origins are both considered.

Traversal is bounded at 200,000 work units and domain expansion at 4,096 units,
with saturation above the threshold. Exhaustion produces `hash-domain-budget`
and incomplete status, never a clean result. Ordinary unsupported effects and
analysis budgets also remain incomplete. A bounded applicability check enables exact typed
digest observation for reachable native hashes with a represented small-domain input leaf, nonempty Bytes inputs that may retain constructed byte leaves, and native hash callbacks. It conservatively enables observation if its scope allowance is exhausted. Observation bypasses general fold compression.
Three exact compressed transfers remain available: a total hash-order choice whose arms hash the same typed
leaves in another order, the native scalar little-endian comparison fold, and the bounded pure-fold join
when all callback alternatives are equal up to the order of direct-digest input items (for example the
standard-library Merkle path fold). Their elided selector, branch-constraint or
byte-partition identities (and identities computed from them) may not reach a published digest input,
a constraint relating them to other values, or a storage key/location; any such dependency reports
`observation-compression-dependency` and leaves the rule incomplete for that entry. Summaries are not
cached across these transfers.
Branch-expanding entries first try a `conservative-absence` certificate (see
docs/coverage.md): a complete conservative may-view in which no evaluated native hash
has a direct input leaf that is a joined value with a raw dependency, or a
represented raw private leaf whose declared domain is small, unless the input also
has two distinct represented raw private leaves whose declarations are never
published raw on any possible sink and never a raw operand of a constraint or
checked narrowing (so both stay private and non-constant on every history).
Otherwise publication, salts and the single-private-leaf condition are ignored, so
a certificate implies no finding on any exact history. Candidates fall back to the exact pass with the remaining
entry allowance; the certificate never reports findings.
It may complete fewer contracts than a scan with this rule disabled under the same budgets;
missing exact input evidence gives `hash-domain-evidence-unavailable`. This rule
consumes immutable typed inputs from the shared native digest transfer; it does
not perform candidate enumeration or contact a contract or author.
