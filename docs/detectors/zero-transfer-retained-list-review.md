# Zero transfer with retained recipient List growth

Availability: opt-in informational review.

The rule flags a supported same-history pattern in which a zero-value transfer
coexists with retained growth of a recipient List. It does not infer that the
List is a reward, balance, or security-critical counter.

A positive amount assertion on the actual sent value, including a later atomic
assertion, excludes the observation. Independent amount parameters, matching
names, shared dependencies and wildcard storage paths cannot establish the
relation. Unknown recipient/key congruence, unsupported effects, exhausted
budgets, checkpoint composition and later overlapping destructive writes
produce incomplete diagnostics. Later List pushes preserve earlier appends.
The observation shares the existing 40,000 entry steps, 256 histories and
50,000 cumulative abstract values across preparation, capture, matching and
emission, without retries.

An application may intentionally record zero-value events or retain a List entry
for bookkeeping. Review the List's role before changing that behavior; the source
relationship alone does not prove a free economic benefit or deployed impact.
