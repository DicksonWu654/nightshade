# Nightshade detector catalog

The current registry contains **96 active rule IDs**: 24 ordinary audit-default rules,
7 additional hygiene rules, 13 policy-dependent rules, 52 other active opt-ins. Counts describe this source checkout.

Without configured OpenZeppelin builtins, the implicit `audit` profile selects
**28 IDs**: 24 ordinary rules plus four policy rules that remain dormant without
matching configuration. `--profile hygiene` selects **35 IDs**, adding seven
source-hygiene rules. Configured builtins also select `openzeppelin-preconditions`.
`--detectors ID,ID` **replaces** profile selection. Choosing every ID includes
experimental reviews; it does not provide complete
security coverage.

Severity is review priority; it does not express the probability or impact of a
vulnerability. Findings are static observations and require contextual review.
See [limitations](limitations.md).

## Audit-default ordinary rules

| Rule | Selection | Severity |
| --- | --- | --- |
| [caller-supplied-deadline](detectors/caller-supplied-deadline.md) | Audit default | medium |
| [circuit-cost](detectors/circuit-cost.md) | Audit default | info |
| [discarded-comparison](detectors/discarded-comparison.md) | Audit default | low |
| [discarded-shielded-send-result](detectors/discarded-shielded-send-result.md) | Audit default | info |
| [duplicate-shielded-mint](detectors/duplicate-shielded-mint.md) | Audit default | medium |
| [duplicated-branch-tail](detectors/duplicated-branch-tail.md) | Audit default | info |
| [either-payload-mismatch](detectors/either-payload-mismatch.md) | Audit default | info |
| [field-recomposition-range-review](detectors/field-recomposition-range-review.md) | Audit default | info |
| [freshness-bound-caller-time](detectors/freshness-bound-caller-time.md) | Audit default | medium |
| [identity-signature-key](detectors/identity-signature-key.md) | Audit default | medium |
| [ignored-validation-result](detectors/ignored-validation-result.md) | Audit default | medium |
| [impossible-assertion](detectors/impossible-assertion.md) | Audit default | medium |
| [ledger-bound-preimage-publication](detectors/ledger-bound-preimage-publication.md) | Audit default | medium |
| [low-entropy-hash-disclosure](detectors/low-entropy-hash-disclosure.md) | Audit default | medium |
| [merkle-leaf-binding-review](detectors/merkle-leaf-binding-review.md) | Audit default | info |
| [merkle-membership-not-enforced](detectors/merkle-membership-not-enforced.md) | Audit default | medium |
| [missing-role-bootstrap](detectors/missing-role-bootstrap.md) | Audit default | low |
| [predictable-commitment-randomness](detectors/predictable-commitment-randomness.md) | Audit default | medium |
| [public-key-membership-authorization](detectors/public-key-membership-authorization.md) | Audit default | high |
| [publicly-derivable-encryption-secret](detectors/publicly-derivable-encryption-secret.md) | Audit default | high |
| [redundant-boolean-branch](detectors/redundant-boolean-branch.md) | Audit default | info |
| [redundant-self-shielded-receive](detectors/redundant-self-shielded-receive.md) | Audit default | info |
| [spoofable-authorization](detectors/spoofable-authorization.md) | Audit default | low / high / critical |
| [zero-amount-set-consumption-review](detectors/zero-amount-set-consumption-review.md) | Audit default | info |

## Additional hygiene rules

These seven are omitted from `audit` and restored by `--profile hygiene`.

| Rule | Selection | Severity |
| --- | --- | --- |
| [always-true-assertion](detectors/always-true-assertion.md) | Hygiene only | info |
| [constant-condition](detectors/constant-condition.md) | Hygiene only | info |
| [dead-code](detectors/dead-code.md) | Hygiene only | info |
| [shadowing](detectors/shadowing.md) | Hygiene only | info |
| [time-dependence](detectors/time-dependence.md) | Hygiene only | info |
| [unnecessary-disclose](detectors/unnecessary-disclose.md) | Hygiene only | info |
| [unused-declaration](detectors/unused-declaration.md) | Hygiene only | info |

## Policy-dependent rules

| Rule | Selection | Severity |
| --- | --- | --- |
| [checkpoint-splits-atomic-update](detectors/checkpoint-splits-atomic-update.md) | Opt-in + policy | low |
| [circuit-work-budget](detectors/circuit-work-budget.md) | Audit; needs policy | low |
| [current-root-policy-mismatch](detectors/current-root-policy-mismatch.md) | Opt-in + policy | medium |
| [declared-secret-publication](detectors/declared-secret-publication.md) | Audit; needs policy | high |
| [forbidden-state-transition](detectors/forbidden-state-transition.md) | Audit; needs policy | medium |
| [openzeppelin-preconditions](detectors/openzeppelin-preconditions.md) | Configured builtins | medium |
| [operation-intent-policy](detectors/operation-intent-policy.md) | Opt-in + policy | info |
| [source-claim-map-getter-review](detectors/source-claim-map-getter-review.md) | Opt-in + policy | info |
| [source-claim-shielded-issuance-review](detectors/source-claim-shielded-issuance-review.md) | Opt-in + policy | info |
| [stale-nft-metadata](detectors/stale-nft-metadata.md) | Opt-in + policy | low |
| [unguarded-sensitive-state-write](detectors/unguarded-sensitive-state-write.md) | Audit; needs policy | high |
| [unsupported-contract-owner](detectors/unsupported-contract-owner.md) | Opt-in + policy | medium |
| [zero-amount-initial-membership](detectors/zero-amount-initial-membership.md) | Opt-in + policy | low |

## Other active opt-ins

Families group related observations; selecting a family is not a CLI shortcut.

### Time and freshness

| Rule | Selection | Severity |
| --- | --- | --- |
| [caller-supplied-time-review](detectors/caller-supplied-time-review.md) | Opt-in | medium |
| [shielded-coin-runtime-width](detectors/shielded-coin-runtime-width.md) | Opt-in | low |

### Authorization, identity and membership

| Rule | Selection | Severity |
| --- | --- | --- |
| [caller-key-zero-entry-review](detectors/caller-key-zero-entry-review.md) | Opt-in | info |
| [closed-membership-capacity-review](detectors/closed-membership-capacity-review.md) | Opt-in | info |
| [configured-membership-capacity-review](detectors/configured-membership-capacity-review.md) | Opt-in | info |
| [enrolled-signature-key-review](detectors/enrolled-signature-key-review.md) | Opt-in | info |
| [membership-identity-binding-review](detectors/membership-identity-binding-review.md) | Opt-in | info |
| [native-key-authentication-review](detectors/native-key-authentication-review.md) | Opt-in | info |
| [quorum-signer-uniqueness-review](detectors/quorum-signer-uniqueness-review.md) | Opt-in | info |
| [signature-key-identity-exclusion-review](detectors/signature-key-identity-exclusion-review.md) | Opt-in | info |
| [split-witness-identity](detectors/split-witness-identity.md) | Opt-in | low |
| [stored-schnorr-key-enrollment-review](detectors/stored-schnorr-key-enrollment-review.md) | Opt-in | info |
| [zero-default-getter-membership-review](detectors/zero-default-getter-membership-review.md) | Opt-in | info |

### Privacy and cryptographic derivations

| Rule | Selection | Severity |
| --- | --- | --- |
| [checked-digest-narrowing](detectors/checked-digest-narrowing.md) | Opt-in | info |
| [conditional-hash-range](detectors/conditional-hash-range.md) | Opt-in | low |
| [generic-witness-maybe-abi](detectors/generic-witness-maybe-abi.md) | Opt-in | low |
| [public-two-component-domain-review](detectors/public-two-component-domain-review.md) | Opt-in | info |
| [published-digest-generator-scalar-review](detectors/published-digest-generator-scalar-review.md) | Opt-in | info |
| [secret-binding-divergence-review](detectors/secret-binding-divergence-review.md) | Opt-in | info |
| [transient-digest-to-ledger](detectors/transient-digest-to-ledger.md) | Opt-in | low |
| [unconstrained-witness-to-state](detectors/unconstrained-witness-to-state.md) | Opt-in | medium |
| [witness-derived-value-review](detectors/witness-derived-value-review.md) | Opt-in | medium |

### Token, coin and value transfers

| Rule | Selection | Severity |
| --- | --- | --- |
| [exported-shielded-descriptor](detectors/exported-shielded-descriptor.md) | Opt-in | info |
| [permissionless-mint-egress](detectors/permissionless-mint-egress.md) | Opt-in | high |
| [received-coin-not-validated](detectors/received-coin-not-validated.md) | Opt-in | low |
| [shielded-burn-amount-width](detectors/shielded-burn-amount-width.md) | Opt-in | info |
| [shielded-contract-recipient-review](detectors/shielded-contract-recipient-review.md) | Opt-in | info |
| [signed-effect-input](detectors/signed-effect-input.md) | Opt-in | low |
| [unbounded-mint](detectors/unbounded-mint.md) | Opt-in | medium |
| [unprotected-value-transfer](detectors/unprotected-value-transfer.md) | Opt-in | low |
| [unshielded-refund-endpoint-review](detectors/unshielded-refund-endpoint-review.md) | Opt-in | info |
| [zero-amount-complementary-send-review](detectors/zero-amount-complementary-send-review.md) | Opt-in | info |
| [zero-amount-unguarded-map-debit-review](detectors/zero-amount-unguarded-map-debit-review.md) | Opt-in | info |
| [zero-amount-unshielded-send](detectors/zero-amount-unshielded-send.md) | Opt-in | info |
| [zero-transfer-retained-list-review](detectors/zero-transfer-retained-list-review.md) | Opt-in | info |

### State and collections

| Rule | Selection | Severity |
| --- | --- | --- |
| [caller-supplied-ledger-equality](detectors/caller-supplied-ledger-equality.md) | Opt-in | medium |
| [destructive-list-reset](detectors/destructive-list-reset.md) | Opt-in | low |
| [inconsistent-keyed-state-guard](detectors/inconsistent-keyed-state-guard.md) | Opt-in | info |
| [mutually-exclusive-terminal-payout](detectors/mutually-exclusive-terminal-payout.md) | Opt-in | high |
| [re-initialization](detectors/re-initialization.md) | Opt-in | low |
| [resettable-list-nonce](detectors/resettable-list-nonce.md) | Opt-in | low |
| [resettable-memo-nonce-review](detectors/resettable-memo-nonce-review.md) | Opt-in | info |
| [shared-module-once-gate](detectors/shared-module-once-gate.md) | Opt-in | info |
| [write-only-ledger](detectors/write-only-ledger.md) | Opt-in | info |

### Source structure and validation

| Rule | Selection | Severity |
| --- | --- | --- |
| [default-recipient-or-owner](detectors/default-recipient-or-owner.md) | Opt-in | medium |
| [exact-balance-threshold](detectors/exact-balance-threshold.md) | Opt-in | info |
| [field-arithmetic-wraparound](detectors/field-arithmetic-wraparound.md) | Opt-in | medium |
| [inconsistent-access-control](detectors/inconsistent-access-control.md) | Opt-in | medium |
| [merkle-insert-without-dedupe](detectors/merkle-insert-without-dedupe.md) | Opt-in | info |
| [nullifier-check-without-insert](detectors/nullifier-check-without-insert.md) | Opt-in | medium |
| [publicly-derived-guard-tag](detectors/publicly-derived-guard-tag.md) | Opt-in | medium |
| [unasserted-security-result](detectors/unasserted-security-result.md) | Opt-in | medium |

Inspect the installed registry or an individual rule with the detector CLI. From
a built source checkout, run:

```sh
node dist/src/cli.js detector list --json
node dist/src/cli.js detector show spoofable-authorization --json
```

Each linked rule page describes its purpose, activation and policy requirements,
common benign matches, and analysis limits. For CLI selection, see the
[user guide](user-guide.md#rules-and-policies).

All current built-in rules have `maturity: experimental`; default selection does
not imply an independently validated accuracy level. `detector list --json` adds
`severity`, `severityLevels`, `confidence` and `maturity`. `severity: varies`
identifies rules with multiple documented grades; `confidence: varies` means no
single confidence is declared for the whole rule. Individual finding grades and
the rule page remain authoritative. Every entry also includes explicit
`defaultEnabled` and `policyRequired` booleans.
