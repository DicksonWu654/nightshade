# enrolled-signature-key-review

Availability: **opt-in**; informational severity, medium confidence. No policy required.

Review an unknown entry-storage snapshot from a whole persistent JubjubPoint Cell
passed to the canonical pinned `jubjubSchnorrVerify`, when no modeled mandatory
check on that exact successful history excludes the identity point. Enrollment
validation in another transaction, trusted initialization or application policy
may make this intentional. The rule does not establish unsafe enrollment, a
known identity key, signature enforcement, sole authorization or exploitability.

Ordinary aliases, helper arguments and retained snapshots preserve immutable
identity. Guards on another key or a new storage revision do not protect an old
snapshot. Mandatory equality constraints and both branch polarities stay within
their original history; checks from mutually exclusive histories are not joined.
An enforced `ecMul(key, scalar) != default<JubjubPoint>` or `ecNeg(key) !=
default<JubjubPoint>` excludes identity of that exact key because the pinned
native operations map identity to identity. This inference says nothing about
subgroup membership, curve membership or off-curve inputs.

The pinned 0.35.0 and 0.35.0-rc.1 canonical verifiers reject identity internally;
their successful calls are quiet. Direct caller or witness keys, transformed
point keys, projected struct fields, collection values, same-named application
circuits and known identity keys are outside this review. The existing
`identity-signature-key` detector continues reporting its known identity evidence.
Source unknowns and exhausted allowances produce explicit incomplete diagnostics.
