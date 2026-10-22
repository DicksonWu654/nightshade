# ADR 0013: Compact strings, input transcoding and original source spans

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Evidence

Compact strings are not JSON strings. Compiler `lexer.ss` accepts either quote
style; escaped quotes/backslashes; `n`, `r`, `0`, `b`, `f`, `t`, `v`; two-digit `x`
and four-digit `u` escapes; and escaped line continuations. Unescaped newlines are
also legal inside strings. Slash and arbitrary identity escapes are not accepted.
Unicode escapes denote scalar characters, not UTF-16 code units. Literal astral
characters are legal, but two surrogate escapes are not an alternate spelling.

`utils.ss` defines the UTF-8 Compact input transcoder with LF line-ending conversion.
Before lexing, CRLF, CR, NEL, CRNEL and Unicode line separator become LF. Paragraph
separator does not. This applies to comments and other source text as well as
strings. An escaped `\r` or `\u2028` is decoded later and remains string data.
`lparser-to-lsrc.ss` encodes the resulting string as UTF-8 bytes and pads with zeros;
padding shorter than that byte sequence is a source error. In particular `\xE9`
denotes é and encodes as two bytes, not a single byte with value 233.

The pinned compiler source revision is
`b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`. Release-compiler tests independently check
acceptance/rejection, and read generated `Uint8Array` constants to compare actual
bytes for the literal, line-ending and padding matrices. Generated JavaScript and
witness implementations are never executed. Scalar escape rejection additionally
has direct decoder-unit coverage grounded in the source character model.

## Implementation

Only the parser decodes source strings. A bounded linear decoder validates all
string/file tokens, including unused declaration bodies and assertion messages.
Owned literal expressions retain decoded `literalString` and optional `paddingSize`
metadata; semantic inference and constant transfer consume those fields rather than
parsing source with JSON or a padding regex. Printable expression/type metadata uses
canonical JSON quoting **after** Compact decoding. This also makes equivalent
escaped Opaque type names share canonical specialization identities.

Includes and quoted external imports share the decoder. Both quote styles retain
external-file semantics; a quoted import cannot accidentally bind to a same-named
local module. Original include/import spans remain available.

The source adapter constructs the compiler-equivalent LF parser view plus a mapping
from its UTF-16 offsets back to original UTF-8 byte offsets. The source file text is
never replaced or written. Node line/column positions use the logical LF view;
columns remain UTF-16 code units. Human code frames use the same line-ending model;
JSON/SARIF retain original byte regions. CRLF/CRNEL contractions and astral characters
are explicitly covered. Normalizing only literal contents would be insufficient:
for example a CR-only line comment must not swallow a following circuit declaration.

The owned `sequences-imports-strings-v3` grammar overlay extends the pinned string
and file token rules to admit backslash-newline continuations. Escape validity is
checked by the decoder, not by permissive grammar tokens. The sequence/import fixes
remain unchanged. Build identity, generated provenance notices and native ABI checks
include this overlay; no installed upstream grammar or generated table is patched.

Padding is checked against decoded byte length before constant transfer. The existing
one-MiB concrete padded-constant cap now also applies to decoded string constants and
produces an explicit `literal-budget` diagnostic when evaluation reaches it, instead
of silently turning a known constant into an unknown value. This analysis bound is
separate from the compiler's `2^24` source sequence-length limit.

## Qualification and limits

`tests/strings.test.ts` contains 70 regressions: 51 complete compiler-valid programs,
16 compiler-rejected programs, one compiler-valid analysis-budget gap and two unit
checks. Complete programs compare cached/uncached facts and instruction/reference
semantic paths and detector observations. Tests cover constant-driven private
branches, predictable commitment randomness, selected imports, includes, Opaque
identity, source regions, human frames and SARIF. The feature fixture adds one
supported compiler-valid root. The previous escaped-Opaque coverage gap is closed.

These tests qualify source semantics, not independent vulnerability labels or proof
execution. Full expression/type legality, wider import search paths and compiler-version
coverage remain open. ADR 0014 subsequently qualifies exported generic schemas and
adds generic casts in the v4 overlay. Decoder and grammar support
does not imply that every operation on every decoded type is modeled.
