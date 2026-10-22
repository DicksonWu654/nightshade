# freshness-bound-caller-time

Availability: **default source/effect review**, no policy required. Severity/confidence: **medium/medium**.

This rule flags an exported circuit that uses caller-supplied time to enforce a
freshness or deadline condition without binding that value to a kernel timestamp
on the same successful path. A parameter name or `Uint<64>` type alone does not
establish that a value is time.

Remediation: bind the supplied time to chain time in the same successful path, or derive the gate from a kernel-bound timestamp. Review both the timestamp-recording and delayed-action circuits.

A deliberate caller-selected time source can match and is not automatically a
defect. The source/effect review does not infer time semantics from names or
comments, follow every helper-mediated constraint, or prove a feasible stale-time
execution.
