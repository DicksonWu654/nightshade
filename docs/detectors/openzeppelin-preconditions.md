# openzeppelin-preconditions

Availability: **opt-in built-in policies required** through `policies.builtins`.
An explicit detector selection must also include `openzeppelin-preconditions`.
Severity **medium**, confidence **high** for the documented precondition evidence.

Checks authenticated OpenZeppelin Compact **0.4.0-alpha.3**, revision
`ec1331cd8195694c747d291e8fc8ab6d2914a976`, including resolved dependency hashes.
It reports universally rejecting application calls with library assertion
evidence, Ownable initialization outside construction, and Initializable import
composition contrary to its documented top-layer/single-importer restriction.

## Example and review scenario

Enable any relevant names under `policies.builtins`:
`openzeppelin-ownable`, `openzeppelin-access-control`, `openzeppelin-pausable`,
or `openzeppelin-initializable`; see [configuration](../configuration.md).

For example, pausing twice can make the second call universally reject. Review
the matched library contract and fix ordering, arguments, or initialization and
import placement. One valid ordering is:

```compact
P__pause();
P__unpause();
```

## False positives and limitations
