# field-arithmetic-wraparound

## Description

This rule reports a directly published Field `+`, `-` or `*` expression when an
operand preserves a nonconstant Uint value through explicit conversion or implicit arithmetic coercion and the successful transaction does
not prove that the unreduced arithmetic stays within the Field range. Compact
Field arithmetic reduces modulo the field; performing a quantity operation in
Field can bypass the rejection behavior of checked unsigned arithmetic.

## Example and scenario

```compact
export circuit decrease(amount: Uint<64>): [] {
  const previous = balance as Uint<64>;
  balance = disclose((previous as Field) - (amount as Field));
}
```

When the amount exceeds the previous quantity, Field subtraction can publish a
large residue instead of rejecting underflow. Prefer checked Uint subtraction
before widening, or assert `previous >= amount` on the same immutable operands.
A later assertion on that same successful transaction also protects an earlier
atomic write. A guard on replacement storage, another Map lookup, or another
invocation of the same arithmetic helper does not protect these operands.

## Evidence and limitations

The shared engine assigns deterministic result identities only from the exact operator
and immutable operand identities/constants; unavailable identities remain fresh.
It retains immutable shallow operator operands, value-preserving
Uint conversion evidence and conservative integer envelopes. Same-pair orders,
scalar equality aliases, successful checked-cast domains on the same immutable
result, inherent ranges of proven scalar equality aliases, and excluded interval endpoints can discharge the rule. Cast domains
protect earlier writes and uncast aliases of that result; a different result or
exclusive history cannot borrow them. Domains are bounded at 256 per history and
charged against the shared abstract-value budget.
Addition/multiplication are safe when their unreduced maximum is below the Field
modulus. A checked result cast only discharges wrapping residues that are all
outside the successful result domain: a cast often rejects small-Uint subtraction
underflow, but addition/multiplication may wrap to small values that pass it.

Only successful histories contribute findings; earlier writes remain observable
when later overwritten. Findings group effects at the same operation site and
entry, without sharing guards between histories or helper invocations. An
exported return is an application output, not necessarily public ledger storage.

This is a bounded quantity-conversion rule, not general arithmetic verification.
Constant-only operations and generic Field-only algebra stay quiet. Nested
operator origins, arithmetic used only inside a hash or condition, arbitrary
quantity intent and algebraic safety identities are outside the shallow contract.
A pure Field balance/amount pair without a preserved Uint conversion is therefore
not covered. A potential interval wrap does not prove a feasible input or a
vulnerability. Intentional modular use of Uint-derived operands may match and
should receive a reasoned suppression after review.

Exact arithmetic and all successful predicates are required. Unsupported evidence
produces `arithmetic-evidence-unavailable`, `arithmetic-domain-incomplete` or
`arithmetic-constraints-incomplete`; review allowance exhaustion produces
`arithmetic-review-budget` or `arithmetic-domain-budget`. The allowance is 200,000 work units, in addition to
normal path/step/value budgets; exhaustion remains incomplete. The structural
applicability scan is bounded and conservatively enables observation if exhausted.
Exact arithmetic observation bypasses specialized compressed hash/fold histories,
so corpus completion must be measured when this rule is enabled.
