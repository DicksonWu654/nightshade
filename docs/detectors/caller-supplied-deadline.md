# caller-supplied-deadline

Availability: **audit default**; no policy required. Severity/confidence:
**medium/medium**.

An exported circuit asserts that a caller-supplied `Uint<64>` time has reached
a deadline computed by adding to ledger data, but does not assert that the
supplied time is at or before protocol block time. A caller may be able to
pass the deadline before the intended chain-time wait has elapsed.

```compact
const deadline = (announcedAt + noticeSeconds) as Uint<64>;
assert(disclose(currentTimestamp >= deadline), "Wait for notice");
```

The rule follows local aliases and casts in the exported circuit and recognizes
an asserted canonical `blockTimeGte` or `blockTimeGt` check of the same time
parameter as an upper bound. It looks for a `Uint<64>` parameter whose name
contains `time` or is `now`; that name is an admission heuristic, not proof
of intended time semantics. Helpers and cross-entrypoint guards are not
substituted, and a quiet result does not certify a timelock. Its source
traversal has a finite allowance and reports exhaustion as a diagnostic.

Check the circuit that records the start time as well as the delayed action.
Bind caller time to protocol block time or compare the ledger deadline
directly with block time.

A known benign match is a circuit that deliberately uses a caller-selected time
for an application-defined delay. The `time` or
`now` parameter-name test is only an admission heuristic; it does not prove that
the value represents protocol time. This local review does not follow helper or
cross-entrypoint checks and does not prove a feasible early execution.
