# Experimental JavaScript API and custom detectors

All JavaScript exports in 0.1.x are **unstable** and can change between minor
releases. Pin the package version and check report schemas when upgrading. The
CLI and its documented reports are the primary integration surface.

| Entry point | Scope |
| --- | --- |
| `nightshade-compact` | `scanFile`, `scanFileIsolated`, options/results and analysis helpers |
| `nightshade-compact/config` | Strict configuration loading, workflows and CI exit policy |
| `nightshade-compact/reporting` | Text, SARIF and structural report formatting |
| `nightshade-compact/detector-api` | Experimental trusted custom-detector contracts and types |

The root also exposes `Program`, `Dataflow`, `atomicUpdateObservations`,
`cachedLedgerUsage`, `balanceThresholds` and related low-level helpers. They
expose implementation details and carry no API stability guarantee. Prefer
`scanFileIsolated` with explicit execution limits for integration with untrusted
inputs; synchronous `scanFile` runs in the caller's process. A worker's heap
setting is not an OS sandbox or an RSS cap.

## Explicit trusted detector modules

`--detector-module FILE` loads and executes a local CommonJS `.cjs` module in the
scan worker. The API equivalent is `ScanOptions.detectorModules`. Both are
explicit opt-ins: ordinary scans and automatically discovered JSON configs do
not load executable detector modules. Never select a module from an untrusted
contract checkout. A module can execute arbitrary JavaScript with the worker's
host permissions; it is not sandboxed by the custom-detector API.

The shipped [zero-total example](../examples/zero-total-detector.cjs) implements
API/facts version 1 and `custom-zero-total-write`. From a trusted built checkout:

```sh
node dist/src/cli.js examples/review/corrected.compact --detector-module examples/zero-total-detector.cjs --detectors custom-zero-total-write
```

This negative example exits 0: the supplied detector finds no zero write to its
selected field. It does not certify the contract. Custom modules must declare
their `custom-` ID, description, required capabilities and `run` function; return
findings with source spans and evidence, and call `context.incomplete` when
required semantics are unsupported. Unsupported API versions, thrown exceptions
and worker limits produce diagnostics. The module contract and owned facts are
unstable alongside the other exported APIs.
