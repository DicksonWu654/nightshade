# re-initialization

Availability: **opt-in**; no policy required. Severity **low**, confidence **low**.
Explicit detector selection replaces the default set.

Owned example: the compiler-qualified [fixture](#example-1)
allows an initializer-named entry to replace stored payload. The
[correction](#example-2) requires the old
`done` flag to be false and retains its true update. Review whether configuration
is intended to be set once; recommendation: enforce that flag invariant when it
is, or document intentional reconfiguration.

Opt-in, low severity and low confidence. From a built source checkout, use:
`node dist/src/cli.js scan examples/review/contract.compact --detectors re-initialization`.

This review selects exported circuit declarations named `initialize`, `initializer`,
or either name followed by an underscore suffix, that transitively write storage.
It evaluates actual modeled construction/default storage, then two calls to that
entry with fresh parameters and witness identities. A finding requires two modeled
successful calls and a potentially different surviving ledger value after the second.
Allocation IDs, revisions and temporary writes alone are insufficient.

```compact
import CompactStandardLibrary;
ledger configured: Field;
export circuit initialize(value: Field): [] { configured = disclose(value); }
```

If `configured` was intended to be set once, a repeated initialization could replace
the application's configuration. The finding does not prove that intention, concrete
path feasibility, deployed reachability or exploitability. Intentional reconfiguration
is a known false-positive shape. Naming is candidate evidence only; this is why the
rule is opt-in and low confidence.

For one-time behavior, assert the old initialization flag and preserve its update on
every successful path. A late assertion on the saved old flag is also effective under
the modeled atomic semantics. Setting and then restoring the flag does not establish
one-time behavior. An idempotent write of the same final value stays quiet.

The analysis retains storage, revisions, collection facts and scalar constraints
across calls. It clears invocation-local guards, environments, call counters and
effect histories. Historical private dependencies retain their original invocation;
they do not become fresh caller evidence or certified trusted storage. Sequence
assertions never contribute to the ordinary `impossible-assertion` rule.

Ordinary entry analysis and the sequence share the existing per-entry step budget;
retained first histories/pairs and abstract values also remain bounded. Exhaustion
is incomplete. Transaction/context effects such as Kernel operations and coin
qualification are not carried across calls. Counter scalar contents, zero updates
and bounded net offsets from fixed checked updates are compared across calls.
Other surviving ADT contents remain unsupported. Either boundary reports explicit incomplete diagnostics and no
initialization finding for that entry. A guarded initializer that has no successful
second call needs no final ADT-content comparison.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/re-initialization.compact`).

```compact
import CompactStandardLibrary;
export ledger payload: Field;
export circuit initialize(value: Field): [] { payload = disclose(value); }
```

### Example 2

Correction (source: `tests/corpus/safe/re-initialization.compact`).

```compact
import CompactStandardLibrary;
ledger done: Boolean;
export ledger payload: Field;
export circuit initialize(value: Field): [] {
  assert(!done, "already initialized");
  done = true;
  payload = disclose(value);
}
```
