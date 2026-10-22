import { spanId, type Expr, type Span, type Statement } from "../model.js";
import type { Program } from "./index.js";
import { naturalValue, numericBound, typeArguments } from "./types.js";

export const CONDITIONAL_HASH_RANGE_RULE = "conditional-hash-range";

export interface ConditionalHashRangeObservation {
  entry: string;
  caller: string;
  hash: Span;
  subtraction: Span;
  inputType: string;
  uintBits: 128;
  slotBytes: 16;
  /** Source branches whose inactive operands lack a recognized invariant. */
  branches: { location: Span; truth: boolean }[];
  sourceUse: { kind: "ledger-write" | "return" | "expression"; location: Span };
}

export type ConditionalHashRangeResult = {
  complete: true; applicable: boolean; work: number; candidateEntries: string[];
  observations: ConditionalHashRangeObservation[];
} | {
  complete: false; applicable: true; work: number; reason: string; candidateEntries: string[];
  observations: [];
};

interface Branch { condition: Expr; truth: boolean; location: Span }
interface Context { branches: Branch[]; assertions: Expr[]; unsupported: boolean }
type BooleanKey = { constant: boolean } | { key: string; truth: boolean };
interface Bounds { minimum: bigint; maximum: bigint }

/** A bounded source relationship, not emitted-slot retention or proof feasibility.
 * Only the reviewed 0.34.0/ZKIR2 direct Uint128 hash layout is qualified. Local
 * immutable aliases are followed, but calls are not interpreted or substituted.
 * Earlier unconditional assertions and safe inactive operand selections can
 * remove this shape; source branches never supply an unconditional invariant. */
export function conditionalHashRanges(program: Program, allowance = 20000): ConditionalHashRangeResult {
  let work = 0, applicable = false;
  const candidateEntries = new Set<string>(), observations: ConditionalHashRangeObservation[] = [];
  const unsupportedCallers = new Set<string>(), conditionalCallers = new Set<string>();
  class Unavailable extends Error {}
  const unavailable = (reason: string): never => { throw new Unavailable(reason); };
  const charge = (amount = 1, depth = 0): void => {
    work += amount;
    if (!Number.isSafeInteger(allowance) || allowance < 0 || work > allowance)
      unavailable("Conditional hash range enumeration exhausted its bounded allowance");
    if (depth > 64) unavailable("Conditional hash range source/alias enumeration exceeds its qualified depth");
  };
  const representation = (type: string | undefined): string => {
    if (!type || type === "unknown") unavailable("Conditional hash range input lacks a resolved schema");
    let current = type!;
    const seen = new Set<string>();
    while (program.nominalTypes.has(current)) {
      charge(program.meteringIdentity(current).length + 1);
      if (seen.has(current) || seen.size >= 32) unavailable("Conditional hash range nominal schema is unavailable");
      seen.add(current); current = program.nominalTypes.get(current)!.underlying;
    }
    if (current === "unknown") unavailable("Conditional hash range input lacks a resolved nominal schema");
    charge(program.meteringIdentity(current).length + 1);
    let nesting = 0;
    for (const character of current) {
      if ("<[".includes(character) && ++nesting > 32) unavailable("Conditional hash range schema exceeds its qualified depth");
      if (">]".includes(character)) nesting--;
    }
    return program.representationOf(type!);
  };
  try {
    charge();
    for (const entry of program.entries) {
      charge();
      const pending = [entry], seen = new Set<string>();
      while (pending.length) {
        charge();
        const caller = pending.pop()!;
        const inheritedConditional = conditionalCallers.has(caller), inheritedUnsupported = unsupportedCallers.has(caller);
        const referenceKey = `${caller}:${inheritedConditional}:${inheritedUnsupported}`;
        if (seen.has(referenceKey)) continue;
        seen.add(referenceKey);
        const fn = program.functions.get(caller), symbol = program.symbols.get(caller);
        if (!fn) {
          if (symbol?.kind === "intrinsic" || symbol?.kind === "witness") continue;
          unavailable("Conditional hash range source references an unresolved callable");
        }
        if (!fn!.declaration.body) unavailable("Conditional hash range source lacks a resolved body");
        const locals = new Map<string, Expr>(), contexts = new Map<Expr, Context>();
        const hashes: Expr[] = [], uses: { value: Expr; kind: "ledger-write" | "return"; location: Span }[] = [];
        const indexExpression = (expression: Expr, context: Context, depth: number): void => {
          charge(1, depth); contexts.set(expression, context);
          if (expression.kind === "call" || expression.kind === "ref") {
            if (!expression.symbol || !program.symbols.has(expression.symbol))
              unavailable("Conditional hash range source contains an unresolved reference");
            if (expression.kind === "call") {
              pending.push(expression.symbol!);
              if (context.unsupported) unsupportedCallers.add(expression.symbol!);
              if (context.branches.length || inheritedConditional) conditionalCallers.add(expression.symbol!);
            }
            if (expression.symbol === "intrinsic::persistentHash") {
              if (program.symbols.get(expression.symbol)?.kind !== "intrinsic")
                unavailable("Conditional hash range native identity is unavailable");
              if (expression.kind === "ref") {
                candidateEntries.add(entry);
                unavailable("Conditional hash range review does not qualify native hash callbacks");
              }
            }
          }
          if (expression.kind === "lambda" && expression.symbol) {
            pending.push(expression.symbol); unsupportedCallers.add(expression.symbol);
          }
          if (["map", "fold"].includes(expression.kind) && expression.args[0]?.symbol)
            unsupportedCallers.add(expression.args[0].symbol!);
          if (expression.kind === "call" && expression.symbol === "intrinsic::persistentHash") hashes.push(expression);
          if (expression.kind === "assign" && expression.name === "=" && expression.ledgerRoot)
            uses.push({ value: expression.args[1], kind: "ledger-write", location: expression.span });
          if (expression.kind === "conditional") {
            indexExpression(expression.args[0], context, depth + 1);
            for (const truth of [true, false]) indexExpression(expression.args[truth ? 1 : 2], { ...context,
              unsupported: true, branches: [...context.branches, {
                condition: expression.args[0], truth, location: expression.args[0].span,
              }] }, depth + 1);
            return;
          }
          // Ternary control, callbacks and loop execution are not qualified by
          // the variable statement-branch compiler experiment.
          const childContext = ["conditional", "map", "fold", "lambda"].includes(expression.kind)
            ? { ...context, unsupported: true } : context;
          for (const argument of expression.args) indexExpression(argument, childContext, depth + 1);
        };
        const plainAssertions = (statement: Statement, depth = 0): Expr[] => {
          charge(1, depth);
          if (statement.kind === "expr" && statement.expr.kind === "assert") return [statement.expr.args[0]];
          if (statement.kind !== "block" && statement.kind !== "bindings") return [];
          const result: Expr[] = [];
          for (const child of statement.body) result.push(...plainAssertions(child, depth + 1));
          return result;
        };
        const indexStatement = (statement: Statement, context: Context, depth = 0): void => {
          charge(1, depth);
          if (statement.kind === "block" || statement.kind === "bindings") {
            const assertions = [...context.assertions]; charge(assertions.length);
            for (const child of statement.body) {
              indexStatement(child, { ...context, assertions: [...assertions] }, depth + 1);
              charge(assertions.length);
              if (!context.branches.length) assertions.push(...plainAssertions(child));
            }
          } else if (statement.kind === "if") {
            indexExpression(statement.condition, context, depth + 1);
            for (const truth of [true, false]) {
              const body = truth ? statement.then : statement.otherwise;
              if (body) indexStatement(body, { ...context,
                branches: [...context.branches, { condition: statement.condition, truth, location: statement.condition.span }] }, depth + 1);
            }
          } else if (statement.kind === "for") {
            if (statement.sequence) indexExpression(statement.sequence, context, depth + 1);
            indexStatement(statement.body, { ...context, unsupported: true }, depth + 1);
          } else {
            if (statement.kind === "bind" && statement.symbol && (!statement.pattern || statement.pattern.kind === "name"))
              locals.set(statement.symbol, statement.expr);
            if (statement.kind === "return") uses.push({ value: statement.expr, kind: "return", location: statement.span });
            indexExpression(statement.expr, context, depth + 1);
          }
        };
        indexStatement(fn!.declaration.body!, { branches: [], assertions: [], unsupported: inheritedUnsupported });
        for (const callee of fn!.calls) {
          charge(); pending.push(callee);
          if (inheritedConditional) conditionalCallers.add(callee);
          if (inheritedUnsupported) unsupportedCallers.add(callee);
        }

        const unwrap = (value: Expr, depth = 0): Expr => {
          charge(1, depth);
          if (value.kind === "disclose" || value.kind === "cast" && value.castKind === "identity") return unwrap(value.args[0], depth + 1);
          if (value.kind === "ref" && value.symbol && locals.has(value.symbol)) return unwrap(locals.get(value.symbol)!, depth + 1);
          return value;
        };
        const key = (expression: Expr, depth = 0): string => {
          charge(1, depth); const value = unwrap(expression, depth);
          if (value.kind === "literal") {
            charge(value.value?.length ?? 0); return `literal:${naturalValue(value.value ?? "") ?? value.value}`;
          }
          if (value.kind === "default" && numericBound(representation(value.type)) !== undefined) return "literal:0";
          if (value.kind === "ref") {
            const target = program.symbols.get(value.symbol!);
            if (!target) unavailable("Conditional hash range operand identity is unresolved");
            // A captured alias reuses this exact read site. A fresh ledger read
            // or witness invocation never shares an identity merely by spelling.
            return target!.kind === "parameter" ? `parameter:${target!.id}` : `read:${program.spanIdentity(value.span)}`;
          }
          if (value.kind === "conditional") return JSON.stringify(["select", booleanKey(value.args[0], depth + 1),
            key(value.args[1], depth + 1), key(value.args[2], depth + 1)]);
          return `value:${spanId(value.span)}`;
        };
        const booleanKey = (expression: Expr, depth = 0): BooleanKey => {
          charge(1, depth); const value = unwrap(expression, depth);
          if (value.kind === "literal" && ["true", "false"].includes(value.value ?? "")) return { constant: value.value === "true" };
          if (value.kind === "default" && representation(value.type) === "Boolean") return { constant: false };
          if (value.kind === "unary" && value.name === "!") {
            const child = booleanKey(value.args[0], depth + 1);
            return "constant" in child ? { constant: !child.constant } : { key: child.key, truth: !child.truth };
          }
          if (value.kind === "binary" && ["==", "!="].includes(value.name!)) {
            for (const index of [0, 1]) {
              const constant = unwrap(value.args[index], depth + 1);
              if (constant.kind !== "literal" || !["true", "false"].includes(constant.value ?? "")) continue;
              const other = booleanKey(value.args[1 - index], depth + 1);
              const positive = (constant.value === "true") === (value.name === "==");
              return "constant" in other ? { constant: other.constant === positive } : { key: other.key, truth: other.truth === positive };
            }
          }
          return { key: key(value, depth + 1), truth: true };
        };
        const bounds = (expression: Expr, inactive?: { key: string; truth: boolean }, depth = 0): Bounds | undefined => {
          charge(1, depth); const value = unwrap(expression, depth);
          if (value.kind === "literal") {
            charge(value.value?.length ?? 0);
            const constant = naturalValue(value.value ?? "");
            if (constant !== undefined) return { minimum: constant, maximum: constant };
          }
          if (value.kind === "default" && numericBound(representation(value.type)) !== undefined) return { minimum: 0n, maximum: 0n };
          if (value.kind === "ref") {
            const bound = numericBound(representation(value.inferredType));
            if (bound !== undefined) return { minimum: 0n, maximum: bound - 1n };
          }
          if (value.kind === "conditional") {
            const condition = booleanKey(value.args[0], depth + 1);
            if ("constant" in condition) return bounds(value.args[condition.constant ? 1 : 2], inactive, depth + 1);
            if (inactive?.key === condition.key) return bounds(value.args[inactive.truth === condition.truth ? 1 : 2], inactive, depth + 1);
            const left = bounds(value.args[1], inactive, depth + 1), right = bounds(value.args[2], inactive, depth + 1);
            if (left && right) return { minimum: left.minimum < right.minimum ? left.minimum : right.minimum,
              maximum: left.maximum > right.maximum ? left.maximum : right.maximum };
          }
          // A branch-local checked cast/arithmetic is not an unconditional
          // domain certificate merely because its inferred type is unsigned.
          return undefined;
        };
        const ordered = (assertion: Expr, left: Expr, right: Expr): boolean => {
          charge(); const value = unwrap(assertion);
          const negate = value.kind === "unary" && value.name === "!";
          const comparison = negate ? unwrap(value.args[0]) : value;
          if (comparison.kind !== "binary") return false;
          if (!negate && comparison.name === "==" || negate && comparison.name === "!=")
            return key(comparison.args[0]) === key(left) && key(comparison.args[1]) === key(right)
              || key(comparison.args[0]) === key(right) && key(comparison.args[1]) === key(left);
          const direct = !negate && [">=", ">"].includes(comparison.name!) || negate && comparison.name === "<";
          const reverse = !negate && ["<=", "<"].includes(comparison.name!) || negate && comparison.name === ">";
          return direct && key(comparison.args[0]) === key(left) && key(comparison.args[1]) === key(right)
            || reverse && key(comparison.args[1]) === key(left) && key(comparison.args[0]) === key(right);
        };
        const safeDifference = (left: Expr, right: Expr, inactive?: { key: string; truth: boolean }): boolean => {
          charge();
          if (key(left) === key(right)) return true;
          const a = bounds(left, inactive), b = bounds(right, inactive);
          return !!a && !!b && a.minimum >= b.maximum && a.maximum - b.minimum < (1n << 128n);
        };
        const sourceHashes = (expression: Expr, found: Set<Expr>, depth = 0): void => {
          charge(1, depth); const value = unwrap(expression, depth);
          if (value.kind === "call" && value.symbol === "intrinsic::persistentHash") { found.add(value); return; }
          // Follow only value-preserving source output shapes, not arbitrary
          // verifier/control uses or arguments to an uninterpreted callable.
          if (["tuple", "struct", "spread"].includes(value.kind))
            for (const child of value.args) sourceHashes(child, found, depth + 1);
          if (value.kind === "sequence") sourceHashes(value.args.at(-1)!, found, depth + 1);
        };
        const hashUses = new Map<Expr, typeof uses[number]>();
        for (const use of uses) {
          charge(); const found = new Set<Expr>(); sourceHashes(use.value, found);
          for (const hash of found) { charge(); if (!hashUses.has(hash)) hashUses.set(hash, use); }
        }
        const subtractions = (expression: Expr, found: Expr[], depth = 0): void => {
          charge(1, depth); const value = unwrap(expression, depth);
          if (value.kind === "binary" && value.name === "-" && numericBound(representation(value.numericType)) !== undefined) found.push(value);
          for (const child of value.args) subtractions(child, found, depth + 1);
        };
        for (const hash of hashes) {
          charge(); const use = hashUses.get(hash) ?? { kind: "expression" as const, location: hash.span };
          const hashContext = contexts.get(hash)!;
          if (!hash.args[0] || !hash.generics) unavailable("Conditional native hash lacks its resolved input schema");
          const found: Expr[] = []; subtractions(hash.args[0], found);
          for (const subtraction of found) {
            charge(); const context = contexts.get(subtraction);
            if (!context) unavailable("Conditional hash subtraction lacks its resolved source context");
            // A caller's branch guards the inlined callee checks too. Source
            // parameter identities alone cannot establish the inactive inputs;
            // do not quietly classify the callee's body as unconditional.
            if (inheritedConditional || inheritedUnsupported) {
              candidateEntries.add(entry);
              unavailable("Conditional hash range review lacks qualified caller/callback control transport");
            }
            const branches = context!.branches.filter(branch => {
              charge(hashContext.branches.length);
              return hashContext.branches.some(other => other.condition === branch.condition && other.truth === branch.truth);
            });
            if (!branches.length) {
              if (context!.unsupported && context!.branches.length) {
                candidateEntries.add(entry);
                unavailable("Conditional hash range review does not qualify transformed ternary/callback control");
              }
              continue; // An unconditionally checked difference is a different shape.
            }
            applicable = true; candidateEntries.add(entry);
            if (program.compilerVersion !== "0.34.0" || program.zkirVersion !== 2)
              unavailable("Conditional hash range review is qualified only for compiler 0.34.0/ZKIR2");
            const entryFunction = program.functions.get(entry);
            if (!entryFunction || !entryFunction.readsState.size && !entryFunction.writesState.size)
              unavailable("Conditional hash range review does not qualify pure source entry/backend retention");
            charge(program.meteringIdentity(hash.generics!).length + 1); const types = typeArguments(hash.generics);
            if (types.length !== 1 || representation(types[0]) !== "Uint<128>"
              || numericBound(representation(subtraction.numericType)) !== (1n << 128n)
              || unwrap(hash.args[0]) !== subtraction)
              unavailable("Conditional hash range review requires the qualified direct Uint128 subtraction/hash schema");
            if (context!.unsupported || hashContext.unsupported)
              unavailable("Conditional hash range review does not qualify loop, callback or ternary control");
            const [left, right] = subtraction.args;
            if (safeDifference(left, right) || context!.assertions.some(assertion => { charge(); return ordered(assertion, left, right); })) continue;
            const missing: ConditionalHashRangeObservation["branches"] = [];
            for (const branch of branches) {
              charge(); const condition = booleanKey(branch.condition);
              if ("constant" in condition) throw new Unavailable("Conditional hash range review does not qualify constant branch retention");
              const active = { key: condition.key, truth: condition.truth === branch.truth };
              let enforced: boolean | undefined;
              for (const assertion of context!.assertions) {
                charge(); const asserted = booleanKey(assertion);
                if (!("constant" in asserted) && asserted.key === active.key) enforced = asserted.truth === active.truth;
              }
              if (enforced === true) continue;
              if (enforced === false) unavailable("Conditional hash range review does not qualify a globally inactive branch");
              if (!safeDifference(left, right, { key: active.key, truth: !active.truth })) missing.push({ location: branch.location, truth: branch.truth });
            }
            if (missing.length) observations.push({ entry, caller, hash: hash.span, subtraction: subtraction.span,
              inputType: types[0], uintBits: 128, slotBytes: 16, branches: missing,
              sourceUse: { kind: use.kind, location: use.location } });
          }
        }
      }
    }
    return { complete: true, applicable, work, candidateEntries: [...candidateEntries], observations };
  } catch (error) {
    if (!(error instanceof Unavailable)) throw error;
    return { complete: false, applicable: true, work, reason: error.message,
      candidateEntries: [...candidateEntries], observations: [] };
  }
}
