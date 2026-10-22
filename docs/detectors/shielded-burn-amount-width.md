# shielded-burn-amount-width

Availability: opt-in. Severity: info. Confidence: high.

Resolved symbol identity excludes user-defined namesakes. Immutable local aliases,
disclosure, identity/widening casts and linear pure helper return forwarding
preserve the exact parameter/recipient identity. Arithmetic, mutable aliases,
non-pure wrapper calls, complex helper control flow, callback bodies and captured parameters are
outside this certificate. Ordinary recipient payments stay quiet.

This is a syntactic type relationship, including source branches and loop bodies,
not a successful-history claim. Intentional small burns can match. Available
balances, feasible transactions, proof success, inability to split burns and
deployed impact are not proved. Review the intended limit before widening an API.
The bounded owned-model pass emits rule-scoped incompleteness on exhaustion.
