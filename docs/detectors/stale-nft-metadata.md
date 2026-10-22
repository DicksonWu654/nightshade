# stale-nft-metadata

Availability: opt-in with an explicit `currentNftMetadata` policy; low severity,
high confidence in the recorded preservation. Reports a separate application
metadata cache that returns the exact payload stored before an authenticated
same-ID NFT burn/remint on one complete modeled successful history.

## Intent and example

Select this rule only when the cache serves the **current incarnation** of a
token. Intentional archives must remain unconfigured. Names, URI contents and
library imports do not establish this intent.

```json
{
  "detectors": ["stale-nft-metadata"],
  "policies": {
    "currentNftMetadata": [
      { "owners": "_owners", "metadata": "cachedURI", "consumer": "replaceToken" }
    ]
  }
}
```

Selectors are unambiguous canonical declaration names or full symbol IDs. The
ownership selector must identify the authenticated NFT instance's `_owners`.
The separate cache must be a root `Map<Uint<128>, Opaque<"string">>` and the
consumer an exported circuit returning `Opaque<"string">`.

```compact
NFT__mint(owner, tokenId);
cachedURI.insert(disclose(tokenId), disclose(oldURI));
NFT__burn(tokenId);
NFT__mint(owner, tokenId);
return cachedURI.lookup(disclose(tokenId));
```

Clear the auxiliary cache during burn, or supply the new incarnation's metadata
before returning it. The pinned NFT already clears its own `_tokenURIs` on burn;
this rule concerns the independently declared application cache.

## Evidence boundary

This rule uses exact NonFungibleToken and Utils
source bytes from compact-contracts revision
`ec1331cd8195694c747d291e8fc8ab6d2914a976`, qualified for
`compact-0.34.0-zkir2`. NFT SHA-256:
`fe4d2b77a34d3f05a3b351d590ad55b2af5ca903c765bcd6946dceedbeecaed1`;
Utils SHA-256:
`215d6374bb22a7c950bb43d046f6380f2c432fb841a2fcead2a35766d159f314`.
Modified providers and namesakes do not acquire the library's lifecycle identity.
A configured relation against either reports a rule-scoped
`nft-metadata-provider-unavailable` diagnostic and no NFT finding. An absent
policy remains not applicable. Untrusted dependency bytes receive the same
incomplete result; provider absence cannot certify a declared relation.

Ordered collection operations and actual writes establish a cache insertion,
canonical burn's zero-owner write, later canonical mint's owner write and final
lookup, all for the same immutable token key and NFT instance. Returned scalar
identity must equal the old inserted payload. Any later potentially overlapping
cache mutation withholds preservation; any potentially overlapping owner write
after remint also withholds it. Different dynamic keys can alias; distinct literal
keys can be proved disjoint. Unknown keys never establish equality.

Observation ordering has a deliberately narrow source boundary: the consumer's
root block contains only expression/binding statements followed by a direct live
cache lookup return. Its key is an effect-free reference, literal or default,
optionally wrapped in casts or `disclose`. Saved reads, helper returns, effectful
lookup keys and root control flow cannot establish this ordering. Unsupported
terminal shapes, unknown relevant keys/values, custom ownership updates,
transaction/context effects, unavailable exact observations, unqualified profiles
and rule allowance exhaustion produce scoped incomplete diagnostics. Baseline and
unrelated rule coverage remain independent.
The observation helper marks its overall result incomplete when it emits any
diagnostic, while retaining supported same-history observations even when another
history for the same ownership/cache/consumer relation is unavailable. Diagnostics
identify that relation in their message and are deduplicated by relation and code.
Allowance exhaustion invalidates the entire bounded pass.

The experimental Counter-query schema 1.2 does not run this isolated observation
pass. An applicable configured NFT consumer therefore reports unavailable
collection observations there; use the normal scanner for this rule.

## Remaining obligations
