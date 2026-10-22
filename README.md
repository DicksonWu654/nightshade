# Nightshade

Nightshade is an offline static security analyzer for Compact, Midnight's smart contract language.

This project extends the Midnight Network with additional developer tooling.

Docs: <DOCS_URL>

[Apache-2.0](LICENSE) | [Download v0.1.1](https://github.com/DicksonWu654/nightshade/releases/tag/v0.1.1)

## What it catches

- [Publishing a private secret used in an authorization check](docs/detectors/ledger-bound-preimage-publication.md).
- [Treating a witness value matching public data as authorization](docs/detectors/spoofable-authorization.md).
- [Discarding a signature verification result](docs/detectors/ignored-validation-result.md).
- [Using caller-supplied time without a chain-time freshness bound](docs/detectors/freshness-bound-caller-time.md).
- [Minting identical shielded outputs in the same transaction](docs/detectors/duplicate-shielded-mint.md).
- [Updating state from Merkle proof data without enforcing membership](docs/detectors/merkle-membership-not-enforced.md).

Findings include source locations and evidence. Review them against your application's intended behavior; all built-in rules are experimental.

## Quickstart

The release package targets Linux x86-64/glibc with Node 22 or 24 and libstdc++ providing `GLIBCXX_3.4.31` or newer (Ubuntu 24.04 or Debian 13). Start in an empty directory with curl and npm available. Installation needs network access; scans use local source and imports, without running contracts or requiring a Compact compiler.

```sh
curl -fL https://github.com/DicksonWu654/nightshade/releases/download/v0.1.1/nightshade-compact-0.1.1.tgz -o nightshade-compact-0.1.1.tgz
npm install --prefix ./.nightshade --no-audit --no-fund ./nightshade-compact-0.1.1.tgz
./.nightshade/node_modules/.bin/nightshade ./.nightshade/node_modules/nightshade-compact/examples/review/contract.compact --fail-on high
```

Expect a medium finding. `--fail-on high` keeps it visible and lets this demo exit successfully. With the default threshold, the same scan exits with a finding status. Use the installed executable on your own contract path next; dependencies must already be available locally. See [getting started](docs/user-guide.md) for imports and configuration, or use a [source build](#source-build) or [Docker](#docker).

## A real finding

```text
MEDIUM
Ledger-bound private preimage is published [ledger-bound-preimage-publication]
examples/review/contract.compact:12:3
  12 |   published = disclose(secret);
     |   ^
Private value from ownerSecret reaches ledger-write published without a hiding transformation.
...
Call path: update
...
Baseline analysis: complete; selected rules: complete.
```

Trimmed from the installed release CLI on the shipped synthetic example. The heading is wrapped and the path shortened. The secret is checked against a ledger hash, then published raw. An intentional reveal protocol can permit this flow; review whether the secret retains any authority.

<a id="output-configuration-and-ci"></a>

## GitHub Action

```yaml
name: Compact analysis
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  nightshade:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: DicksonWu654/nightshade@v0.1.1
        with:
          path: contracts
          fail-on: medium
          category: compact-contracts
```

Change `contracts` to your source directory and install your contract's dependencies before scanning. The Action builds Nightshade, uploads SARIF and preserves the scan exit code. Upload needs GitHub code-scanning access and the permissions shown above. Pin the Action to a reviewed commit for an immutable dependency. See the [Action guide](docs/user-guide.md#github-action).

## Supported compiler versions

Pinned profiles: **0.28.0, 0.29.0, 0.30.0, 0.31.1, 0.33.0-rc.2, 0.34.0, 0.35.0-rc.1 and 0.35.0**. Each covers a bounded subset. ZKIR2 is the default; ZKIR3 requires explicit selection and is qualified only for 0.34.0. Select the profile used to build your application. See the [profile matrix](docs/compiler-onboarding.md#supported-profiles).

## Limitations

- A complete scan means the selected, supported analysis finished. It does not prove contract security, compiler validity or that a reported path can execute.
- Unsupported syntax, unresolved imports and exhausted budgets produce diagnostics. Check baseline and per-rule coverage even when no findings appear. Incomplete analysis fails by default; an explicit rule-warning policy retains gaps in reports.
- Path and value tracking are bounded. Some native operations and dynamic calls are incomplete; there is no general cross-transaction or cryptographic proof.
- Default checks do not infer your full authorization policy. Credential-changing circuits can go unreported. Declare required `authorization` policy and review those circuits explicitly.
- Intentional disclosures can resemble defects. No independently established release-wide precision or recall estimate exists. Read the [evaluation and its sampling caveats](docs/evaluation.md) and [detailed limitations](docs/limitations.md).

## Links

- [User guide](docs/user-guide.md), [configuration](docs/configuration.md) and [rule catalog](docs/detectors.md).
- [Changelog](CHANGELOG.md), [contributing](CONTRIBUTING.md) and [architecture](docs/architecture.md).
- [Report a security issue privately](SECURITY.md).
- [License](LICENSE), [notices](NOTICE) and [third-party attribution](THIRD_PARTY.md).

### Source build

From a source checkout, use Node 22 or 24, npm, Git, Python, make and a C/C++ compiler:

```sh
npm ci
npm run build
npm run demo
```

Installation and build download pinned dependencies and tools. The demo checks the shipped positive and corrected example.

### Docker

From a source checkout with Docker available, build and scan with:

```sh
docker build --platform linux/amd64 -t nightshade:local .
docker run --platform linux/amd64 --rm --network none -v "$PWD:/project:ro" nightshade:local examples/review/contract.compact
```

On macOS, use this Linux image. Mount local imports alongside your source. The shipped positive exits with a finding status. Other native platforms need a separately qualified build.
