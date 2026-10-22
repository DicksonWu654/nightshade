# missing-role-bootstrap

Availability: default-on; low severity, high confidence. Reports an authenticated
ShieldedAccessControl instance that initializes in every successful constructor
history but has no entry-reachable route to seed any role. With an empty role
tree, guarded `grantRole` cannot establish the first role holder.

## Example and scenario

```compact
import "access/ShieldedAccessControl" prefix SAC_;
constructor(salt: Bytes<32>) { SAC_initialize(salt); }
export circuit grant(role: SAC_RoleIdentifier, account: SAC_AccountIdentifier): [] {
  SAC_grantRole(role, account);
}
```

Initialization stores state and salt; it does not insert an initial role holder.
The library's documented constructor calls `_grantRole` separately.

## Recommendation

Seed an initial role holder, usually `DEFAULT_ADMIN_ROLE`, with `_grantRole` during
construction. Custom seeded roles and deliberate delayed setup are valid
alternatives. Review the intended administrator relationships separately.

## Evidence and known false positives

Requires compiler profile `compact-0.34.0-zkir2`, exact ShieldedAccessControl and
Utils source bytes from compact-contracts revision
`ec1331cd8195694c747d291e8fc8ab6d2914a976`, and complete successful constructor
histories containing the canonical initialization write. The rule stops at the
authenticated guarded `grantRole` boundary. Any other reachable raw `_grantRole`
call or application reference to that instance's storage withholds the absence
claim, even in dead source branches, zero-iteration loops and captured callback
bodies. This check walks owned source statements rather than the pruned CFG.
The upstream test mock deliberately exposes
delayed bootstrap and remains quiet. Modified libraries and namesakes are outside
this rule's identity scope.

This rule does not assess seed adequacy, custom libraries, arbitrary access
policies, missing initialization, or whether off-chain deployment procedures
correctly perform a deliberately exposed setup operation.
