# received-coin-not-validated

Availability: **opt-in** with `--detectors received-coin-not-validated`; no policy
required. Severity **low**, confidence **low**. Explicit selection replaces the
default detector set.

Owned example: the compiler-qualified [fixture](#example-1)
adapts an SDK deposit with an owned fixed-payment requirement, then substitutes a
tautological amount check. The [correction](#example-2)
checks the expected color and value `10` before receipt. Review a fixed-price
payment flow; recommendation: constrain the exact received coin to the intended
trusted terms. The original unrestricted SDK deposit is not labeled vulnerable.

For example, a payment circuit that calls `receiveShielded(disclose(coin))`
without checking its price can accept a payment outside the intended terms.
Check `coin.color == expectedColor` and `coin.value >= price` against trusted
ledger terms or constants. The rule also recognizes exact value equality and
positive constant lower bounds. It does not prove those terms implement the
intended business policy.

Evidence comes from completed entry histories, canonical standard-library call
identity, exact received operands and enforced predicates. Equality aliases,
helpers, negated comparisons, branch alternatives and checks after receipt are
supported. Later checks constrain atomic success. Checks on another coin,
ignored comparisons, self-equality, `Uint >= 0`, arbitrary caller-supplied terms
and self-written ledger values do not establish validation. Exhausted query or
analysis budgets remain incomplete.

Known limits: custom receipt protocols, unshielded receipts, arithmetic-derived
pricing and arbitrary policy inference are outside this rule. A generic wallet,
forwarder, donation or deposit handler may intentionally accept any coin.
Select explicitly with `--detectors received-coin-not-validated`.

The compiler-valid positive/corrected/lookalike cases live in the existing corpus.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/received-coin-not-validated.compact`).

```compact
// SDK shielded-map fixture with an owned fixed-payment policy; see known-bugs.json.
import CompactStandardLibrary;

export ledger counter: Counter;
export ledger reward: QualifiedShieldedCoinInfo;

witness dummy(): [];

export circuit deposit(coin: ShieldedCoinInfo): [] {
  assert(coin.color == default<Bytes<32>>, "expected color");
  assert(coin.value == coin.value, "expected amount");
  receiveShielded(disclose(coin));
  reward.writeCoin(disclose(coin), right<ZswapCoinPublicKey, ContractAddress>(kernel.self()));
  counter.increment(1);
  dummy();
}
```

### Example 2

Correction (source: `tests/corpus/safe/received-coin-not-validated.compact`).

```compact
// SDK shielded-map fixture with an owned fixed-payment policy; see known-bugs.json.
import CompactStandardLibrary;

export ledger counter: Counter;
export ledger reward: QualifiedShieldedCoinInfo;

witness dummy(): [];

export circuit deposit(coin: ShieldedCoinInfo): [] {
  assert(coin.color == default<Bytes<32>>, "expected color");
  assert(coin.value == (10 as Uint<128>), "expected amount");
  receiveShielded(disclose(coin));
  reward.writeCoin(disclose(coin), right<ZswapCoinPublicKey, ContractAddress>(kernel.self()));
  counter.increment(1);
  dummy();
}
```
