# permissionless-mint-egress

Availability: **opt-in effect review**, no policy required. Severity/confidence: **high/low**.

The rule correlates a canonical mint effect with an unguarded token egress effect. It requires an unguarded mint authority and a completed successful history; beneficiary or buyer predicates may guard the egress. It recognizes named supply/treasury state, a shared token domain, or a same-root permissionless pair as the stored-value boundary. Standard-library mint/send wrappers are mapped back to their user call sites; internal mint claims and output-counter lowerings are not treated as separate withdrawals.

Remediation: bind mint and egress to an authenticated role or protocol state, and enforce the supply/custody invariant across both circuits. An amount cap alone does not establish that invariant.

Intentionally permissionless minting, treasury flows, or public claims can match
when they meet the structural conditions. Review the intended supply and custody
policy before treating the finding as a defect. The analysis does not establish
runtime feasibility, asset loss, or deployed impact.
