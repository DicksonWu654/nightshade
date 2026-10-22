# source-claim-shielded-issuance-review

Availability: **opt-in**, **policy-required**; severity **info**. Select
`--detectors source-claim-shielded-issuance-review` and configure an explicit policy:

```json
{
  "sourceClaims": [{
    "kind": "non-transferable-shielded-issuance",
    "circuit": "issue",
    "quote": "// Contract claim: recipients cannot transfer issued coins to other parties."
  }]
}
```

A known benign mismatch is a policy quote that overstates transfer restrictions.
It can yield an expected
mismatch review. Confirm the claim's intended meaning and source location; the
detector checks the supplied policy against represented code and does not infer
broader transfer or deployment semantics.

The policy supplies claim meaning. The analyzer does not interpret prose or infer
intent from names, paths, omitted transfer circuits, or other source conventions.
The selector must resolve uniquely to a canonical exported circuit. The quote
must equal one complete parser-owned comment, including delimiters, in that
circuit's declaration file immediately before the declaration, with only
whitespace between the comment and declaration. Arbitrary exact quotes are
supported when the policy explicitly supplies this claim kind.

A finding pairs that comment with a canonical `mintShieldedToken` invocation on
a complete modeled successful entry history whose fourth argument has exact
native type `Either<ZswapCoinPublicKey, ContractAddress>` and an active left
(user-key) tag. Literal tags and mandatory final successful-history Boolean
constraints supply evidence, including checks after the mint. Helpers, aliases
and nonempty callbacks use ordinary call transfers. Aborted histories and
zero-iteration callbacks do not contribute successful invocations.

Compact **0.34.0/ZKIR2 or ZKIR3** is supported. Missing history evidence, opaque
tags or layouts, unresolved calls, applicable unsupported profiles, checkpoints,
unfinished baseline semantics and exhausted allowances produce incomplete
rule-scoped diagnostics. Experimental Counter-query histories lack this rule's
selected evidence and cannot certify a configured observation. Preparation,
original-string UTF-8 adjacency inspection, capture, constraint matching and
emission share **40,000 steps per entry, 256 paths per entry, and 50,000 cumulative
values per rule**, with no retry. Default and unselected scans do not run this rule.
