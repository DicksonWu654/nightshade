# zero-amount-initial-membership

Availability: **opt-in policy**. Severity/confidence: **low/high**. Select with
`--detectors zero-amount-initial-membership` and declare intended zero semantics:

```json
{"version":1,"policies":{"zeroAmountMembership":[
  {"circuit":"credit","amount":"amount","map":"balances"}
]}}
```

The rule reports when **every modeled full successful invocation of the selected
entry, with its declared amount input fixed to zero, requires the same exact Map
entry to have been present initially**. At least one modeled zero success is
required. Other inputs and initial storage remain unknown. This is ordinary
bounded abstract interpretation, with no solver, transaction execution or
cross-transaction proof. The actual amounts passed to helpers retain their values:
an entry-zero call can still pass `amount + 1` to a helper.

```compact
export ledger balances: Map<Bytes<32>, Uint<64>>;
export circuit credit(key: Bytes<32>, amount: Uint<64>): [] {
  const old = balances.lookup(disclose(key));
  balances.insert(disclose(key), disclose((old + amount) as Uint<64>));
}
```

If zero operations must succeed without an existing balance/allowance entry,
bypass lookup **and membership assertions** at zero, or supply the entry locally.
A member assertion still requires initial membership. An optional
`if (balances.member(key)) { ... }` is quiet when its absent route completes;
prior insertion also supplies the entry and stays quiet. Intentional rejection
is a known policy-dependent review shape; do not enable the policy for it.

This diagnostic does not establish that an entry is missing in deployment, that
any modeled history is concretely feasible, or that a runtime failure occurs.

Only an exported circuit, scalar `Uint`/`Field` amount parameter and root Map
ledger can be selected. Nested Map receivers have separate outer/inner atoms.
Successful lookup preconditions are captured **before** membership refinement.
Required saved member predicates retain their original query/write position.
Ordered insertions, descendant value writes and known-empty receiver replacement
are distinguished; wildcard keys, may-alias writes, unknown nested replacements,
lost predicate structure and exhausted evidence remain explicitly unavailable.
Reached checkpoints are unavailable because committed prefixes do not establish
full entry success. No zero success normally supplies no clean rule result.
One narrow exception certifies intentional rejection: an unconditional direct
`Uint` amount comparison against zero fails with the exact declared input fixed
to zero, while a separate complete ordinary analysis retains successful
invocations. Both analyses share the step/value budgets, and the failed assertion
remains in the evidence. Unrelated always-failing entries, contradictory guards,
missing identity, reached checkpoints and exhausted evidence stay unavailable.

The observation uses the existing budgets (40k steps/256 paths/50k values by
default), including evidence traversal. Multiple declared inputs share entry work
and the rule's value allowance. Storage summaries and compressed fold/hash/source
histories are disabled until they can preserve these precondition snapshots.
Both engines and cached/uncached modes have regression coverage. Rule failures
remain rule/entry-scoped and do not change baseline default completion.
