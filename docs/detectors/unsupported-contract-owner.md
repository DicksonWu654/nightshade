# unsupported-contract-owner

Availability: **opt-in policy**; severity **medium**, confidence **high** for the
final selected tag and authenticated guard behavior. Concrete feasibility remains
unproved.

## Description, example and scenario

```compact
Ownable__unsafeTransferOwnership(right<Bytes<32>, ContractAddress>(next));
```

For an owner selected by `callableOwnable`, a complete modeled successful history
leaves the pinned Ownable owner's active arm as `ContractAddress`. Its
`assertOnlyOwner` implementation explicitly rejects that arm, including nonzero
contract addresses, while this owner value remains stored. The library's unsafe
API is intentional; the policy declares that this particular owner guard must
remain usable with the current implementation.

Evidence uses OpenZeppelin Compact 0.4.0-alpha.3 revision
`ec1331cd8195694c747d291e8fc8ab6d2914a976`, exact Ownable and Utils bytes, and the
qualified Compact 0.34.0/ZKIR2 profile. The rule reviews configured application
invariants; it does not claim an upstream defect or a newly confirmed
vulnerability.

## Configuration and recommendation

Select `unsupported-contract-owner` explicitly and declare:

```json
{ "callableOwnable": [{ "owner": "_owner" }] }
```

The selector must resolve to a root native
`Either<Bytes<32>, ContractAddress>` ledger. Use its exact symbol ID when multiple
instances make `_owner` ambiguous. Arrays must be dense and contain at most 64
owners; duplicate selectors for the same resolved owner are deduplicated.
Authentication failures remain rule-scoped incomplete rather than quietly
passing the declared obligation.

Keep the selected owner in the account-identifier arm and use the safe
ownership-transfer circuit. Intentional authority suspension, migration staging
for future C2C support and test exposures should remain outside this policy.
Declaring a policy without selecting this opt-in rule does not run the rule.

## Evidence and limitations

Ordered state writes establish the final surviving discriminator for each
selected instance and successful history. Whole-owner writes and aggregate
reconstructions are compiler-qualified, including constructor and direct
authenticated ledger assignments. Exact regional discriminator/payload facts
are handled separately; their controls are synthetic because the pinned
compiler rejects direct native Either field assignment. Payload-only mutations
preserve the discriminator. A later
left discriminator, safe replacement or canonical left/zero renunciation stays
quiet. Rejected histories cannot supply a finding.

Bounded successful-constant projection uses the same immutable snapshot and
history, including later atomic assertions. It cannot borrow constraints from a
different ledger revision, branch, wildcard region or module instance. Unknown
final tags, unknown overlapping regions, absent invocation locations,
incomplete entries, unsupported profiles and exhausted observations produce
rule-scoped incomplete diagnostics. Supported findings for independent
relations and histories remain available.

The real-source seed triple is an owned focused mutation of the pinned OZ
MockOwnable test wrapper. Its nonzero right owner is independent of the existing
default-address rule; corrected and unrelated-ledger controls remain quiet.
