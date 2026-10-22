# ADR 0010: Canonical generic call identities and exact natural values

Status: implemented for compiler 0.34.0 / language 0.26.0, 2026-09-25.

## Problem

Generic circuits and witnesses were cached by generic argument text. Consequently,
`identity<Uint<8>>` and `identity<Uint<0..256>>` created two analyzer functions even
though the qualified compiler generates one. This split call graphs, duplicated
summary contexts and made named witness/authorization policies spuriously ambiguous.
Module instances already used semantic argument equality (ADR 0009); callable
instances must use the same rule without conflating distinct declarations.

Numeric spellings also had inconsistent treatment. The source grammar accepts
binary, octal and uppercase hexadecimal literals, but constant analysis and generic
kind checking did not consistently recognize them. Decimal loop bounds were converted
to JavaScript numbers too early: adjacent large integers could collapse to the same
number and incorrectly appear to describe a zero-iteration loop.

## Compiler evidence

At pinned compiler revision `b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`,
`expand-modules-and-types.ss`'s `make/register-frob` registers a function instance
through `instance-table-cell`. Type arguments compare with `sametype?`; natural
arguments compare numerically. The instance table belongs to a declaration, not
its visible import alias or body text. Distinct enclosing module instances can
therefore define distinct generic functions with otherwise identical bodies.

The release executable is qualified separately from this ahead-of-release source:
`generic-specializations.test.ts` compiles synthetic applications and counts generated
method definitions, including asynchronous stateful methods and witness wrappers.
Equivalent Uint bounds, tuple/vector shapes and phantom generic types share methods;
different bounds, nominal declarations, used generic fields and typed empty vectors
retain separate methods. No generated contract or witness implementation is executed.

`lexer.ss` accepts decimal and `0b`/`0B`, `0o`/`0O`, `0x`/`0X` literals. It rejects
leading-zero decimals and checks Field range separately. Compiler-backed numeric
regressions verify ordinary argument types, natural specialization, radix loops,
padded UTF-8 strings and malformed syntax. The compiler accepts a one-iteration
loop with bounds 9007199254740992 and 9007199254740993; our number-based CFG cannot
represent those bounds exactly and now explicitly rejects analysis of it.

## Representation and transfer guarantees

Each generic declaration has a specialization table of canonical argument lists and
canonical symbols. Modules and callables share the same semantic argument-comparison
helper. Lookup reuses an existing symbol before cloning/binding a new declaration.
Registration precedes body binding so recursive references still encounter the same
identity and existing recursion/depth/analysis budgets remain effective.

Ordinary and map/fold references enter this same binding path. Selected, renamed and
prefixed imports do not introduce a second declaration identity. Different original
declarations and different enclosing module instances remain distinct. The first
equivalent spelling determines the internal specialized ID; IDs are not claimed to
be stable across source reordering or formatting.

Shared declaration identity never means shared witness invocation identity. Each
dynamic witness application still creates a fresh private source, with the exact
call/reference span. Privacy policies select the canonical declaration and apply
to all its invocations. Distinct specializations still require explicit symbol IDs
when a name-based policy is ambiguous. No new disclosure rule is introduced.

The natural-value helper uses BigInt and normalizes types, generic arguments,
literal constants and numeric policy constants without floating-point conversion.
Type-range whitespace is normalized. Policy strings retain their existing allowance
for leading-zero decimals; this does not legalize those literals in Compact source.
Loop bounds become numbers only when safely representable, otherwise analysis emits
`loop-range`. Existing loop-count and padded-string allocation limits are unchanged.

## Qualification and remaining limits

Accepted applications compare cached/uncached complete path facts and
instruction/reference semantic paths, plus detector observations. Tests cover pure
and stateful summary reuse, named policies, aliases, higher-order targets, exact
Unicode spans and fresh witnesses. A composed feature fixture joins these mechanisms.
Numeric tests cover known commitments, impossible assertions and state transitions
through existing analyses rather than special-casing detectors.

This is bounded compiler conformance, not a full source type-legality checker, a
whole-language generic inference implementation, independent security labels or
qualification of other compiler releases. General state-dependent summaries,
correlated joins, broader imports/platforms and legal/release review remain separate
gates. Keep incomplete results visible rather than rounding unsupported values or
dropping their effects.
