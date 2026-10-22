# unprotected-value-transfer

Availability: **opt-in** with `--detectors unprotected-value-transfer`; no policy
required. Severity **low**, confidence **low**. Explicit selection replaces the
default detector set.

Owned example: the compiler-qualified [fixture](#example-1)
exposes a canonical send without a required private caller predicate. Its
[correction](#example-2) checks a
private-key hash against stored owner data. Review whether the transfer is meant
to be restricted; recommendation: enforce the intended caller/protocol check
where required, and preserve documented public faucets or forwarding behavior.

The requested rule reviews successful exported invocations of the canonical
Compact standard-library `mintShieldedToken`, `mintUnshieldedToken`, `sendShielded`,
`sendUnshielded` and `sendImmediateShielded` when no required caller-dependent
check constrains the operation. It must identify actual operation reaches, including
nested calls and replay; a user-defined helper with the same name is not a token
operation. Constructors are outside the exported-operation claim.

A condition merely mentioning a private value is insufficient. A branch with both
arms reaching the same operation must not manufacture a required guard. Conversely,
alternate real authentication in different arms and a late assertion constraining
atomic success must remain valid. Successful predicates need full private-input
scope; witness-only facts omit parameter checks. Effects and constraints must remain
on the same history, and exhausted analysis must stay explicitly incomplete.

An unguarded public faucet or mint can be intentional. This rule cannot infer that
transfers should be private or privileged, or verify arbitrary cryptographic or
protocol checks.

## Evidence query and limits

Actual kernel/native histories identify canonical token helper invocations. An
exported entry and operation form one group; nested invocation chains remain in the
finding. Internal `sendShielded` calls inside `sendImmediateShielded` do not create
a duplicate operation finding.

Within each identical recorded public context, the bounded predicate-cover query
checks whether the union of successful histories covers every Boolean valuation
of their recorded private conditions. This cancels irrelevant reconverging branch
choices while retaining an assertion, disjunction, branch-only transfer or
alternative checks. Repeated witness invocations remain distinct atoms. The query
reads completed histories; it does not execute new paths, solve numeric conditions
or infer cryptographic validity. It excludes pinned stdlib recipient/change branches
by canonical function identity, not source names. Application reuses of those
conditions remain visible even when prior assumptions have refined them to constants.
Literal truths and immutable self-equalities supply no constraint. Missing expression
identity is opaque evidence, never an invented equality between unrelated values.

The result means **no required predicate in this recorded application evidence**.
Implicit overflow/cast/transaction checks still apply. The rule does not prove path
feasibility or intended authorization. Arbitrary algebraic relationships between
atoms, distinct but equivalent public contexts and opaque predicates can prevent
a report. Private dependency does not certify a check's strength as authentication.
The `spoofable-authorization` rule separately reviews raw witness equalities.

Observation uses scope `all` and the existing engine value budget. Applicability
is bounded to 20,000 graph operations; each cover query to 100,000 operations/depth
64 and condition keys to 65,536 characters before and after composition; total rule
work to 1,000,000 operations. Missing invocation/predicate evidence,
unsupported effects and exhaustion remain explicitly incomplete. A failed cover
query returns no partial rule findings. Existing correlated/Counter domains do not
execute these token operations and may certify their structural absence; their
admission scope is unchanged.

## Usage, example and correction

```sh
node dist/src/cli.js scan examples/review/contract.compact \
  --detectors unprotected-value-transfer
```

Explicit `--detectors` selects that set rather than adding to defaults. Include
other desired IDs in the comma-separated selection. The CLI marks this rule as
`opt-in review`; JSON detector metadata has `defaultEnabled: false`.

```compact
import CompactStandardLibrary;
export circuit withdraw(recipient: Either<ContractAddress, UserAddress>): [] {
  sendUnshielded(default<Bytes<32>>, 1, disclose(recipient));
}
```

This is a review match when selected. If withdrawal should be restricted, enforce
the intended caller or protocol check. The corrected corpus fixture asserts a
private-key hash against stored owner data before sending. Public faucets and
payment/forwarding flows should retain their intended policy; an opt-in match alone
is not a reason to add an owner restriction. User-defined namesake helpers are quiet.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/unprotected-value-transfer.compact`).

```compact
import CompactStandardLibrary;
export circuit withdraw(recipient: Either<ContractAddress, UserAddress>): [] {
  sendUnshielded(default<Bytes<32>>, 1, disclose(recipient));
}
```

### Example 2

Correction (source: `tests/corpus/safe/unprotected-value-transfer.compact`).

```compact
import CompactStandardLibrary;
export ledger owner: Bytes<32>;
witness secret(): Bytes<32>;
export circuit withdraw(recipient: Either<ContractAddress, UserAddress>): [] {
  assert(persistentHash<Bytes<32>>(secret()) == owner, "owner");
  sendUnshielded(default<Bytes<32>>, 1, disclose(recipient));
}
```
