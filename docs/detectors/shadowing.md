# shadowing

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the resolved binding observation.
Use `--min-severity low` to hide informational findings, or
`--detectors shadowing` to select only this rule.

Reports a root-file local or parameter whose name hides an outer binding.
Resolved lexical scopes and imported aliases determine which binding is hidden.

## Example and review scenario

The compiler-0.34.0-qualified owned [Counter fixture](#example-1)
has a ledger `round` and a `read(round: Field)` parameter. The
[correction](#example-2) makes the
data source clearer:

```compact
export circuit read(value: Field): Field { return value; }
```

Review same-named parameters near ledger access or authorization helpers where
a reader might mistake a caller-supplied value for state. Recommendation: give
the inner binding a distinct name and check that each reference resolves to the
intended declaration.

## False positives and limitations

Constructor/API parameter names and small local scopes often shadow intentionally.
The finding establishes a naming relationship, not incorrect binding, a security
defect or a required rename. Only root-file observations are reported. Exhausted
source traversal remains incomplete.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Counter fixture (source: `tests/corpus/informational/shadowing-positive.compact`).

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

export circuit read(round: Field): Field { return round; }
```

### Example 2

Correction (source: `tests/corpus/informational/shadowing-corrected.compact`).

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

export circuit read(value: Field): Field { return value; }
```
