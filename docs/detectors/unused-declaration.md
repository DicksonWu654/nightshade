# unused-declaration

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the source-reference observation.
Use `--min-severity low` to hide informational findings, or
`--detectors unused-declaration` to select only this rule.

Reports a root-file ledger, witness or private circuit with no source reference
in the compilation unit. Exported circuit APIs are exempt; a source reference
does not have to execute to count as a use.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
adds `ledger stale: Field;` without a reference. Its
[correction](#example-2)
removes that declaration. Review unused state or helpers after an API refactor.

Recommendation: remove stale declarations or restore their intended use after
checking application and off-chain consumers.

## False positives and limitations

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/unused-declaration-positive.compact`).

```compact
// This file is part of midnightntwrk/example-counter.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma language_version >= 0.20;

import CompactStandardLibrary;

// public state
export ledger round: Counter;

// Nightshade owned informational regression; adapted from example-counter.
ledger stale: Field;
export circuit increment(): [] {
  round.increment(1);
}
```

### Example 2

Correction (source: `tests/corpus/informational/unused-declaration-corrected.compact`).

```compact
// This file is part of midnightntwrk/example-counter.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma language_version >= 0.20;

import CompactStandardLibrary;

// public state
export ledger round: Counter;

// Nightshade owned informational regression; adapted from example-counter.
export circuit increment(): [] {
  round.increment(1);
}
```
