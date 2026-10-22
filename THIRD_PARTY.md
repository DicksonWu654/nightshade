# Third-party materials

Runtime dependencies:

- `tree-sitter` 0.25.1 (MIT), installed as npm alias `tree-sitter-runtime`,
  including its native parser runtime. This avoids the grammar's stale optional peer.
- `node-gyp-build` 4.8.4 (MIT) loads/builds the native parser addon.
- Generated parser derived from official `midnightntwrk/compact-tree-sitter` at
  `22de6ee9dbf4b92fe4e2fe3602e53f1e352b79fd` (Apache-2.0), with an owned overlay
  correcting two-element sequences, empty import selections, escaped string line
  continuations, generic cast targets, omitted tuple pattern slots and empty struct
  patterns, generic-call disambiguation in argument/tuple lists, empty struct
  declarations and emit expressions. Packed artifacts preserve the upstream grammar,
  notices and Apache license in `dist/parser`, plus the overlay/binding sources.
  Generated C is build output, not checked-in source. See ADR 0003.
- Generated tree-sitter runtime headers (MIT) include their license in
  `dist/parser/LICENSE.tree-sitter`.
- Compact 0.34.0 standard library sources (Apache-2.0), copied without changes
  from LFDT-Minokawa/compact commit `1f671fc27818df2b2676b3a97f85b2b821756243`
  (`compactc-v0.34.0`), are in `src/stdlib` and copied into `dist/src/stdlib`.
  The original copyright and license headers are retained. The ZKIR3 file is
  parsed separately; its presence does not establish ZKIR3 semantic qualification.
- `standard-library-0.28.compact` is unmodified Apache-2.0 source from
  `compactc-v0.28.0`, commit `dce2f11d28460d6379e45e770952a2fbbe1d2ecd`.
  Its SHA-256 is `949f46cfc1f7878a374a9b924b5b48a843ff058bf7962d4156206630f469fc80`.
  Original copyright/licence headers are retained; release archive and related
  native/ledger source identities are in `scripts/compiler-sources.json`.
- `standard-library-0.29.compact` is unmodified Apache-2.0 source from
  `compactc-v0.29.0`, commit `f17a98c1c1557c4a1e4bf391e0018543aa358bdd`.
  Its SHA-256 is `9150c4c9c0bea961e5631980349aca27c5e509423946b6880f3205be2d78eb13`.
  Original copyright/licence headers are retained; release archive and related
  native/ledger source identities are in `scripts/compiler-sources.json`.
- The historical `standard-library-0.30.compact` is also unmodified Apache-2.0
  source, byte-identical at compiler 0.30.0 commit
  `705c2274b5f7bf6c309f9811143b1832281f7876` and 0.31.1 commit
  `0da5b0452eb0c1053d42418bf34b12cc29c7d63e`. Its original notice is retained.
  Release archives and stdlib/native/ledger source hashes are recorded in
  `scripts/compiler-sources.json`; binaries remain external development inputs.
- The `standard-library-0.33-rc.2.compact` is unmodified Apache-2.0 source
  from `compactc-v0.33.0-rc.2`, commit
  `566ef0eb66c3442e189b5e2d7ae9e1b99426db26`. Its original notice is retained;
  archive, binary and stdlib/native/ledger hashes are in `scripts/compiler-sources.json`.
  The executable prints unstamped 0.33.0; this is RC2, not a stable release.
- The shared `standard-library-0.35-rc.1.compact` is unmodified Apache-2.0
  source from both `compactc-v0.35.0` and `compactc-v0.35.0-rc.1`, commit
  `debb05f9414b9d1e176741c2be289bb32233f0fc`. Its original notice is retained;
  release archive and native/ledger source hashes are in `scripts/compiler-sources.json`.
  Both profiles cover a ZKIR2 subset; whole-language and 0.35 ZKIR3 remain unqualified.
- Transitive native binding/build dependencies are pinned in `package-lock.json`;
  retain their distributed license files when packaging a release.

Development dependencies include the pinned upstream grammar (Apache-2.0),
tree-sitter-cli 0.25.10 (MIT), TypeScript (Apache-2.0), Node type declarations
(MIT), Ajv 8.20.0 and ajv-draft-04 1.0.0 (both MIT) for output-schema tests.
The draft-04 adapter validates the external SARIF schema in its declared dialect.
The external official SARIF
schema is used only when explicitly supplied; it is not redistributed here.
Complete dependency notices are included in the installed dependency packages.

OpenZeppelin's analyzer and Slither are architecture references; their code is not
linked, forked or copied into Nightshade. The OpenZeppelin scanner is a separate
comparison executable. Official documentation and compiler sources are references.
The received-coin positive/corrected fixtures in `tests/corpus` adapt
`packages/contracts/src/test/resources/shielded-map.compact` from Midnight JS
commit `997164501d21573772a82094d4aaa1744afdd64b` (Apache-2.0). The owned changes
add a fixed-payment policy and replace one amount check with a tautology; source
identity and changes are recorded in `tests/corpus/known-bugs.json`. These test
fixtures are not included in the npm package. The upstream notice is:

> Copyright 2023 IOHK
>
> Licensed under the Apache License, Version 2.0 (the "License”). You may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.txt
>
> Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Apart from the explicitly identified parser, library and adapted fixture sources,
the synthetic corpus and analyzer implementation are original work.

The informational fixtures in `tests/corpus/informational` adapt Midnight
Foundation's Apache-2.0 `example-counter`, commit
`273f083ab36a52407f16ec9a9796d902226e05d6`, `contract/src/counter.compact`.
Each preserves the upstream copyright/license header. The owned mutations,
source hash and detector expectations are in `tests/corpus/known-bugs.json`.
They illustrate lint/review defects, not upstream vulnerabilities, and are not
included in the npm package.

Upstream research checkouts, release binaries and generated compiler artifacts are
kept outside this repository. The original project is licensed under Apache-2.0;
see `LICENSE` and `NOTICE`. Dependency and adapted-source licences still apply.
Third-party licences and notices apply to the corresponding bundled materials.

The additional owned seeds in `tests/corpus/known-bugs` adapt the same SDK and
Counter inputs, and the Apache-2.0 bulletin-board example at commit
`02690a5ab7e5b845febfb5d6cf48420dd4e95faa`, `contract/src/bboard.compact`.
Original notices are retained. Added policy/setup and mutations are recorded in
`tests/corpus/known-bugs.json`; these fixtures are excluded from the npm package.

The Pausable seed adapts OpenZeppelin `MockPausable.compact` from commit
`ec1331cd8195694c747d291e8fc8ab6d2914a976`; its original MIT notice follows:

MIT License

Copyright (c) 2025 Zeppelin Group Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

The `tests/corpus/known-bugs/digest-key/` modules and their registration
controls are owned synthetic examples under this project's Apache-2.0 licence.
