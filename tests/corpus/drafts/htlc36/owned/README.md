# HTLC lifecycle regression expectations

The positive fixture has two required public-key equality guards. These expected
locations are fixed independently of detector output:

- Receiver guard: `htlc-positive.compact:36`
- Sender guard: `htlc-positive.compact:48`

The corrected and lookalike fixtures should produce no spoofable-authorization
finding. The lifecycle tests check both guard expressions, compare these locations
with the corpus manifest, and retain native spending and ledger effects across
both analysis engines, cached transfers and supervised scans.
