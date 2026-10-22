# discarded-shielded-send-result

Availability: **default**; informational severity, high confidence in the source
observation. No policy required.

Informational source-use review; no policy required. Select it alone with
`--detectors discarded-shielded-send-result`.

The rule observes discarded results from canonical stdlib `sendImmediateShielded`
and `sendShielded`, and coin descriptors from `mintShieldedToken`, in structurally
reachable root-source circuits. It recognizes
expression statements (including transparent disclosure/identity casts) and unused
immutable local identity alias chains. Imported aliases keep canonical identity;
custom same-name helpers do not match. A helper consisting only of an exact
return of a producer or another transparent helper also qualifies. Helpers with
setup, branches, partial field returns or computed returns remain outside.
Any non-alias reference, including field
selection, assignment, capture or return, conservatively retains the result.

The returned `ShieldedSendResult` contains `sent: ShieldedCoinInfo` and
`change: Maybe<ShieldedCoinInfo>`. Review whether the application needs that
metadata. Discard does not establish lost funds, spendability or exploitation:
wallet or transaction machinery may independently retain metadata. A use of one
field silences the rule without proving all metadata is handled correctly.
Returning the original input coin does not retain a discarded output descriptor.

This bounded source pass has a separate mode/cache and preserves ordinary,
validation and comparison allowances. It shares existing constant-source reach,
short-circuit and definite-rejection handling. Sequence-prefix discard, arbitrary
forwarding helpers, recipient policy and off-chain retention are outside scope.
Callback reach is structural and does not prove execution or nonzero iterations.
Exhaustion yields an incomplete-rule diagnostic and no findings. Main and Counter
scans route this rule through source-only analysis; no engine transfer changes.
