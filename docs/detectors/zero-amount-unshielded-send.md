# zero-amount-unshielded-send

Availability: **opt-in**; severity **info**. This rule reviews canonical
`CompactStandardLibrary.sendUnshielded` calls whose amount retains zero in its
modeled successful-history range. The amount is the second argument (index 1).

```compact
sendUnshielded(disclose(color), disclose(amount), disclose(recipient));
```

An unsigned amount permits zero until an effective constraint excludes it.
A literal zero is also a review candidate. Require `amount > 0` before sending
when the intended operation requires a positive amount, or handle zero explicitly
without invoking the send. A local circuit sharing the spelling is not the
canonical operation.

Zero-valued transfers can be intentional for protocol bookkeeping or a supported
no-op. This informational rule reports only the modeled source amount; it does
not infer application policy, prove a transaction can execute, or establish
economic impact. Unsupported histories and exhausted budgets remain incomplete.
