# public-key-membership-authorization

Availability: **default-on**, no policy required. Severity/confidence: **high/high**.
This is a static trust-boundary review candidate. `soleGate` stays **unproven**;
authentication intent, concrete path feasibility and deployed exploitability are
not established. Select this rule alone with
`--detectors public-key-membership-authorization`.

The rule reports a raw canonical native `ownPublicKey` used as the active key of
a required public Map/Set membership query on every modeled successful reach of
an affected effect invocation. Membership in public identity storage does not
establish possession of a secret. Other protocol checks can still apply.
Findings group the enforcing predicate site and exported entry, list affected
ledger/kernel effect invocations and preserve each matching history's immutable
receiver/key, ledger revision, native witness invocation and actual effect positions.

The first boundary is deliberately small:

- Exact completed entry histories under `equivalent-states`, with all predicates
  and existing collection observations. Constructor setup is excluded.
- Canonical `intrinsic::ownPublicKey`, with one exact raw native leaf. Keys may be
  the native `ZswapCoinPublicKey`, its unchanged `Bytes<32>` payload or canonical
  `Either<ZswapCoinPublicKey, ContractAddress>` with a known active public-key arm
  and a default inactive contract-address payload.
- A definite preexisting ledger receiver, no preceding ledger writes
  (`writesBefore === 0`), an unchanged receiver/query revision, and an exact
  immutable collection address. Wildcard regions do not establish equality.
- The exact query-result identity must be required true on that same history.
  Direct assertion/branch polarity, negation and literal Boolean comparison are
  supported. Arbitrary Boolean equalities or compound/unknown encodings are not
  inferred. Optional, bypassed, ignored and negative membership stay quiet.
- Query evaluation must precede its enforcing predicate. The predicate must
  precede each affected write or kernel operation by its recorded write/operation
  positions. Every successful reach of the exact effect invocation is intersected
  before source grouping. Different histories are never merged into one gate.

Arbitrary user witnesses, entry-selected retrieval/payment identities, namesakes,
private-secret hash identities, transformed native keys, inactive Either payloads,
and general lookup-only membership are outside this rule. A supported raw native
membership guard can still be intentional public-identity validation; review the
protocol role. The rule does not establish intended privilege, secrecy/entropy,
replay safety or a sole authentication gate. Guards after effects and receivers
queried after ledger writes remain outside this first release.

Exact observations use the existing entry-isolated rule pass and original
40,000-step/256-path/50,000-value limits; entries share the rule's value allowance.
Consumer matching/intersection is bounded to 1,000,000 checks, with immutable
operand/address traversals limited to 4,096 nodes and depth 32 and Boolean decoding
to depth 64. Exhaustion or missing required invocation evidence produces
rule/entry-scoped incomplete diagnostics and discards that entry's partial
findings. Baseline completion and existing detector findings are preserved.

Acceptance includes optional/bypassed branches, distinct calls/keys/receivers,
changed current storage, nested summary replay, inactive/custom encodings,
operation chronology, scoped budgets and instruction/reference × cached/uncached
agreement. The detector analyzes source evidence; it does not run a witness,
runtime, proof, transaction or exploit reproduction.

Direct facts consumers also use the bounded structural Map/Set applicability
check before requiring observations. Definite absence creates no missing-evidence
error; an exhausted check remains incomplete. This preserves existing List-only
registry consumers without weakening evidence for applicable contracts. The
existing closed terminal-Counter grammar excludes witness calls, including natives;
its experimental scan reuses that `no-witnesses` absence certificate. Other shapes
still fall back to exact analysis; no Counter grammar or budget is broadened.
