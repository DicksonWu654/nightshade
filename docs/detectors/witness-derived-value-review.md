# Witness-derived value review

Opt-in, low-confidence review. Flags a canonical send whose recipient comes directly from a witness result or its projection without an earlier exact equality assertion binding it to a ledger-derived value on the same branch. Prover-selected recipients can be intentional; the rule does not establish payment policy or review every amount source.

Uses canonical send and witness identities, local aliases and separate branch states. Direct calls are supported; helper-mediated constraints are outside this review. Unsupported loops and exhausted traversal budgets produce diagnostics.
