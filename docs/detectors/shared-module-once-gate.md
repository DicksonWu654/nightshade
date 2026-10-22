# Shared module once gate

Availability: **opt-in** with `--detectors shared-module-once-gate`.
Severity: **info**. Confidence: **high** for the resolved source fact.

Two distinct importing module instances expose direct wrappers calling the same
canonical gate. The supported gate body consists exactly of an assertion that a
Boolean ledger flag is false followed by an assignment of true to that flag.
The assertion message must be parser-confirmed literal data; every operand has
an exact supported shape. Wrappers and gates accept no arguments and return [].
Resolved module, import and call identities distinguish shared gates from
separate instances.
No names or assertion messages establish initialization intent.

A successful gate write contradicts its next false-state guard unless storage is
reset. This does not prove an actual cross-transaction failure, independent
initialization intent, or deployed compiler behavior. Intentional shared
initialization receives the same review finding. Multiple aliases of a single
wrapper module are quiet because they do not create distinct importing modules.
Distinct compiler path/module identities remain distinct even when physical
parsing shares bytes.
