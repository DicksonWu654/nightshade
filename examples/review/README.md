# Nightshade example project

From a built repository checkout, run `npm run demo`. It verifies
[expected.json](expected.json) against both programs and exits 0 on success.
The demo prints complete reports including per-rule coverage; the last line
confirms `Demo passed`. Individual scans use the ordinary CLI exit codes: the positive exits 1, the
corrected program exits 0, and incomplete analysis exits 2.

`contract.compact` asserts a hash of a witness secret equals a ledger credential,
then writes the raw secret to public ledger storage. Expected: one
`ledger-bound-preimage-publication`, medium severity, line 12, column 3.
`corrected.compact` writes only its persistent digest; expected: zero findings.
Both use the 0.34.0/ZKIR2 profile. A Compact compiler is not needed to run the demo;
compiler acceptance is checked separately during qualification.

```sh
npm run --silent scan -- examples/review/contract.compact --json
npm run --silent scan -- examples/review/corrected.compact --json
```

These are owned, synthetic examples derived from the compiler-grounded
[positive](contract.compact) and
[digest-only correction](corrected.compact) fixtures. Intentional reveal
protocols can match the positive. Publishing a digest is not a universal secrecy
proof. The correction is a negative for this rule, not a claim that the contract
is secure. [Rule contract](../../docs/detectors/ledger-bound-preimage-publication.md).
