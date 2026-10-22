# Unasserted security result

Opt-in, low-confidence review. Flags a comparison or canonical predicate discarded before a ledger write/send, persisted as data, or returned inside an aggregate after an effect without earlier enforcement of that exact predicate. A Boolean-returning predicate API is allowed. Recording a status can be intentional; the rule does not infer security intent from names.

Uses resolved expressions, local aliases and separate branch states. Direct calls are supported; helper-mediated constraints are outside this review. Unsupported loops and exhausted traversal budgets produce diagnostics.
