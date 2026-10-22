# write-only-ledger

Availability: **opt-in**; no policy required.
Severity **info**, confidence **high** for the source read/write observation.
Select with `--detectors write-only-ledger`.

Public ledger fields commonly serve DApps and indexers without a Compact source
read. The corpus confirms source facts, not actionable dead state; default
promotion requires a review showing that most matches are actionable.

Reports an ordinary Cell ledger field with explicit source writes and no source
read in the analyzed Compact compilation unit. Initialization or later writes
can make a declaration appear used while circuit logic ignores its stored value.
This extends `unused-declaration`, which treats mutation targets as references.

## Example and review scenario

For example, a configurable role can be stored while its getter returns a constant:

```compact
sealed ledger administratorRole: Bytes<32>;
constructor(role: Bytes<32>) { administratorRole = disclose(role); }
export circuit getRoleAdmin(): Bytes<32> {
  return default<Bytes<32>>;
}
```

Review whether the getter should return the setting.
This detector covers the
no-read subset; reading that field in another circuit withholds a finding even
if the getter still ignores it.

## Recommendation and limitations

Read the stored value where its circuit behavior is intended. Retain intentional
off-chain metadata and document its consumers. Off-chain indexers, wallets,
TypeScript ledger readers and external application logic are outside this scan;
the finding does not establish useless storage, a security defect, or that writes
can safely be deleted.

All represented helper and callback bodies count, including source-excluded
paths, zero-iteration callbacks and functions not reachable from an entrypoint.
Reads through snapshots, arguments, explicit methods and projections count.
Native ADTs such as Counter and Map are excluded. One finding groups concrete
canonical instances of the same declaration; any represented instance read
withholds it. Same names in distinct declarations do not merge.

Unbound generic/module bodies retain semantic instance and include context;
one instantiated sibling cannot certify another body's read absence. Defining
bindings distinguish unrelated same-name fields, and unknown references/import
aliases are screened conservatively. Uncertain source evidence or missing bodies is explicitly
rule-scoped incomplete, not a certified absence. Work/depth exhaustion discards
the pass's findings and reports incomplete; its allowance is separate from other
informational source rules and baseline transfer completion.
