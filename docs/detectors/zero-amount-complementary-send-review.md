# zero-amount-complementary-send-review

Availability: **opt-in**; severity **info**. Select it with
`--detectors zero-amount-complementary-send-review`.

The rule reports one complementary pair of canonical
`CompactStandardLibrary.sendUnshielded` calls on a complete original successful
invocation history. The calls use the same exact immutable token-color operand
and send unsigned scalar snapshots `P` and `T-P`. Aliases and value-preserving
casts retain the relationship. The exact total `T` must have a proven positive
modeled lower bound, and **both actual sent amount envelopes must have lower
bound zero** after all modeled mandatory checks, including late checks.

```compact
assert(disclose(total) > 0 as Uint<128>, "positive total");
const remainder = total - part;
sendUnshielded(disclose(color), disclose(part), disclose(recipient));
sendUnshielded(disclose(color), disclose(remainder), disclose(recipient));
```

Review whether the application's allocation policy should conditionally skip
exact zero endpoint sends. Intentional zero/full endpoint allocations may match.
A guard that makes either sent amount positive quiets this rule. A literal-zero
part with a positive total is quiet because its remainder is strictly positive.
Independent fee amounts, different color snapshots, mutually exclusive calls,
and Field subtraction do not establish the selected relationship.

Supported profiles are Compact **0.31.1/ZKIR2** and **0.34.0/ZKIR2 or ZKIR3**.
Admission counts possible canonical calls through helpers and callbacks, including
zero-iteration callbacks. Closures without an unsigned subtraction or two
possible canonical sends can establish structural absence
without requesting a numeric profile. Original histories remain separate; cached
and uncached transfers preserve the same operands and evaluation order. Exact
read/storage summaries remain available; fresh computed scalar occurrences are
interpreted rather than reused from cached results.

Preparation, execution, immutable-key traversal, numeric bounds, pair matching,
and emission share the existing **40,000 steps per entry, 256 paths per entry,
and 50,000 cumulative values per rule**. Unsupported applicable profiles,
checkpoints, lost arithmetic lineage, inconsistent or missing history carriers,
unfinished baseline analysis, and exhausted allowances produce rule-scoped
incomplete diagnostics. Experimental Counter-query histories do not supply this
rule's exact observation evidence.
