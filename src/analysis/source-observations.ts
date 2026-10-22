import type { Expr, Pattern, ScopeAst, Span, Statement } from "../model.js";
import { spanId } from "../model.js";
import type { Program, SymbolInfo } from "../semantic/index.js";
import { naturalValue } from "../semantic/types.js";
import { returnedSchnorrVerifier } from "../semantic/signature-targets.js";
import { returnedShieldedResult } from "../semantic/shielded-result-targets.js";
import { LocalResultUses } from "../semantic/local-result-uses.js";
import { duplicatedBranchTails } from "./branch-tails.js";
import { redundantBooleanBranch } from "./boolean-branches.js";
import { binaryConstant, castConstant, literalConstant, type Constant } from "../dataflow/constants.js";

export type SourceObservationKind = "unused-declaration" | "dead-code" | "shadowing" | "unnecessary-disclose" | "constant-condition" | "ignored-validation-result" | "discarded-comparison" | "duplicated-branch-tail" | "redundant-boolean-branch" | "discarded-shielded-send-result";
export interface SourceObservation { kind: SourceObservationKind; location: Span; message: string; metadata: Record<string, unknown> }
const sourceCache = new WeakMap<Program, ReturnType<typeof sourceObservations>>();
const validationCache = new WeakMap<Program, ReturnType<typeof sourceObservations>>();
const comparisonCache = new WeakMap<Program, ReturnType<typeof sourceObservations>>();
const shieldedSendCache = new WeakMap<Program, ReturnType<typeof sourceObservations>>();
type SourceMode = boolean | "comparisons" | "shielded-send-results";
/** Share the bounded source pass across source-only rules in a scan. */
export function cachedSourceObservations(program: Program, mode: SourceMode = false): ReturnType<typeof sourceObservations> {
  const cache = mode === "shielded-send-results" ? shieldedSendCache : mode === "comparisons" ? comparisonCache : mode ? validationCache : sourceCache;
  let result = cache.get(program);
  if (!result) { result = sourceObservations(program, 200000, mode); cache.set(program, result); }
  return result;
}

interface Value { constant?: Constant; public: boolean; assertionFails?: boolean }
interface Context { values: Map<string, Value>; names: Map<string, SymbolInfo>; circuit: string; publicControl: boolean }
const unknown = (): Value => ({ public: false });

/** Source-only observations are intentionally separate from path proofs. Work is
 * bounded, and only root-file declarations are linted (imports retain their own
 * public API). Constant folding shares the engine's typed scalar operations.
 * Unknown loops/callbacks invalidate local constant knowledge. No call result,
 * private input or aggregate selection is invented as a constant. */
export function sourceObservations(program: Program, allowance = 200000, mode: SourceMode = false): { complete: boolean; observations: SourceObservation[]; work: number } {
  const observeValidation = mode === true, observeComparisons = mode === "comparisons";
  const observeShieldedSend = mode === "shielded-send-results";
  const observeResults = observeValidation || observeComparisons || observeShieldedSend;
  let work = 0, complete = true;
  const observations: SourceObservation[] = [], used = new Set<string>(), unresolvedNames = new Set<string>();
  const charge = (depth = 0) => { if (++work > allowance || depth > 128) complete = false; return complete; };
  const resultUses = observeResults ? new LocalResultUses(charge) : undefined;
  const root = program.rootSource.path;
  const emit = (kind: SourceObservationKind, location: Span, message: string, metadata: Record<string, unknown> = {}) => {
    if (location.file === root || kind === "duplicated-branch-tail") observations.push({ kind, location, message, metadata });
  };
  const refs = (expr: Expr, depth: number, retainResult = true, owner?: string): void => {
    if (!charge(depth)) return;
    if (expr.symbol) { used.add(expr.symbol); if (retainResult) resultUses?.reference(expr.symbol); }
    else if (expr.span.file === root && (expr.kind === "ref" || expr.kind === "call") && expr.name) unresolvedNames.add(expr.name);
    if (expr.ledgerRoot) used.add(expr.ledgerRoot);
    for (const child of expr.args) refs(child, depth + 1, retainResult, owner);
    if (expr.body) references(expr.body, depth + 1, expr.kind === "lambda" ? expr.symbol : owner);
  };
  const references = (statement: Statement, depth = 0, owner?: string): void => {
    if (!charge(depth)) return;
    if (statement.kind === "block" || statement.kind === "bindings") statement.body.forEach(child => references(child, depth + 1, owner));
    else if (statement.kind === "if") { refs(statement.condition, depth + 1, true, owner); references(statement.then, depth + 1, owner); if (statement.otherwise) references(statement.otherwise, depth + 1, owner); }
    else if (statement.kind === "for") { if (statement.sequence) refs(statement.sequence, depth + 1, true, owner); references(statement.body, depth + 1, owner); }
    else refs(statement.expr, depth + 1, !resultUses?.bindAlias(statement, owner), owner);
  };
  for (const fn of program.functions.values()) if (fn.declaration.body) references(fn.declaration.body, 0, fn.symbol.id);
  // Uninstantiated generic bodies have source references but no FunctionInfo.
  // Unresolved names are conservative may-uses, never invented symbol bindings.
  const sourceReferences = (scope: ScopeAst, depth = 0): void => {
    if (!charge(depth)) return;
    for (const declaration of scope.declarations) {
      if (!charge(depth)) return;
      if (declaration.body) references(declaration.body, depth + 1);
      if (declaration.scope) sourceReferences(declaration.scope, depth + 1);
    }
  };
  sourceReferences(program.rootSource.ast);
  const retainedResults = resultUses?.retained() ?? used;
  if (!complete) return { complete, observations: [], work };
  const usedSites = new Set([...used].flatMap(id => { const symbol = program.symbols.get(id); return symbol ? [spanId(symbol.declaration?.span ?? symbol.span)] : []; }));
  const exportedSites = new Set<string>();
  for (const symbol of program.exportedSymbols()) {
    if (!charge()) break;
    exportedSites.add(spanId(symbol.declaration?.span ?? symbol.span));
  }
  for (const symbol of program.symbols.values()) {
    if (!charge()) break;
    if (symbol.span.file !== root || !["ledger", "witness", "circuit"].includes(symbol.kind) || unresolvedNames.has(symbol.name) || usedSites.has(spanId(symbol.declaration?.span ?? symbol.span)) || program.entries.includes(symbol.id)) continue;
    if (symbol.kind === "circuit" && (symbol.declaration?.exported || exportedSites.has(spanId(symbol.declaration?.span ?? symbol.span)))) continue;
    emit("unused-declaration", symbol.span, `${symbol.kind} ${symbol.name} has no reference in this compilation unit`, { symbol: symbol.name, declarationKind: symbol.kind });
  }
  const copy = (ctx: Context): Context => ({ values: new Map(ctx.values), names: new Map(ctx.names), circuit: ctx.circuit, publicControl: ctx.publicControl });
  const bind = (id: string | undefined, ctx: Context, value: Value): void => {
    if (!id) return;
    const symbol = program.symbols.get(id); if (!symbol) return;
    const previous = ctx.names.get(symbol.name) ?? program.lexicalBinding(ctx.circuit, symbol.name, charge);
    if (!complete) return;
    if (previous && previous.id !== id) emit("shadowing", symbol.span, `${symbol.name} shadows an outer ${previous.kind} declaration`, { shadowed: previous.span, shadowedKind: previous.kind });
    ctx.names.set(symbol.name, symbol); ctx.values.set(id, value);
  };
  const pattern = (node: Pattern, ctx: Context, depth: number): void => {
    if (!charge(depth)) return;
    bind(node.symbol, ctx, unknown()); node.children.forEach(child => pattern(child, ctx, depth + 1));
  };
  type Discard = "expression-statement" | "unused-binding" | "unused-alias-chain" | "sequence-prefix";
  const expression = (expr: Expr, ctx: Context, depth: number, discardedBy?: Discard): Value => {
    if (!charge(depth)) return unknown();
    if (expr.kind === "literal") return { constant: literalConstant(expr), public: true };
    if (expr.kind === "ref") return ctx.values.get(expr.symbol!) ?? { public: program.symbols.get(expr.symbol!)?.kind === "ledger" };
    // A sequence evaluates left to right and returns only its final result.
    // Prefix comparisons are discarded even in a consumed/returned sequence.
    // A definite rejection stops source reach before the remaining components.
    if (expr.kind === "sequence") {
      let result = unknown();
      for (const [index, arg] of expr.args.entries()) {
        result = expression(arg, ctx, depth + 1, index === expr.args.length - 1 ? discardedBy : "sequence-prefix");
        if (result.assertionFails) break;
      }
      return result;
    }
    if (expr.kind === "binary" && ["&&", "||"].includes(expr.name!)) {
      const left = expression(expr.args[0], ctx, depth + 1);
      if (left.assertionFails) return left;
      if (left.constant?.kind === "boolean") {
        const rightNeeded = left.constant.value === (expr.name === "&&" ? "true" : "false");
        return rightNeeded ? expression(expr.args[1], ctx, depth + 1) : left;
      }
      // The RHS is optional. Its definite rejection cannot terminate the
      // short-circuit route; its effects also cannot update all-route constants.
      const right = expression(expr.args[1], copy(ctx), depth + 1);
      ctx.values.clear(); return { public: left.public && right.public };
    }
    if (expr.kind === "conditional") {
      const condition = expression(expr.args[0], ctx, depth + 1);
      if (condition.assertionFails) return condition;
      if (condition.constant?.kind === "boolean") return expression(expr.args[condition.constant.value === "true" ? 1 : 2], ctx, depth + 1);
      const yes = expression(expr.args[1], copy(ctx), depth + 1), no = expression(expr.args[2], copy(ctx), depth + 1);
      ctx.values.clear(); return { public: condition.public && yes.public && no.public, assertionFails: !!yes.assertionFails && !!no.assertionFails };
    }
    // Callback effects cannot update the straight-line constant environment.
    if (expr.kind === "map" || expr.kind === "fold" || expr.kind === "lambda") {
      for (const arg of expr.args) {
        const value = expression(arg, copy(ctx), depth + 1);
        if (value.assertionFails) return value;
      }
      ctx.values.clear(); return unknown();
    }
    const transparent = expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity";
    const args: Value[] = [];
    for (const arg of expr.args) {
      const value = expression(arg, ctx, depth + 1, transparent ? discardedBy : undefined);
      if (value.assertionFails) return value;
      args.push(value);
    }
    if (expr.kind === "disclose") {
      if (args[0]?.public && ctx.publicControl) emit("unnecessary-disclose", expr.span, "Disclosure operand is already public from literals or direct ledger data", { evidence: "source-public-operand" });
      return args[0] ?? unknown();
    }
    if (expr.kind === "assert") return { public: false,
      assertionFails: args[0]?.constant?.kind === "boolean" && args[0].constant.value === "false" };
    if (expr.kind === "assign") {
      const target = expr.args[0];
      if (target.kind === "ref" && program.symbols.get(target.symbol!)?.kind === "local") ctx.values.delete(target.symbol!);
      return unknown();
    }
    if (expr.kind === "binary") {
      let constant = binaryConstant(expr.name!, args[0]?.constant, args[1]?.constant, program.representationOf(expr.numericType ?? expr.inferredType ?? "unknown")) ?? undefined;
      if (observeComparisons && discardedBy && !constant && ["==", "!=", "<", "<=", ">", ">="].includes(expr.name!) && owner && reachable.has(owner)) {
        emit("discarded-comparison", expr.span,
          "This comparison's Boolean outcome is discarded; this use does not enforce it. Operand evaluation and its effects or constraints remain.",
          { operator: expr.name, discardedBy, evidence: "resolved-source-unused-comparison-result" });
      }
      return { constant, public: args.every(arg => arg.public) };
    }
    if (expr.kind === "unary" && expr.name === "!") return { constant: args[0]?.constant?.kind === "boolean" ? { kind: "boolean", value: String(args[0].constant.value !== "true") } : undefined, public: !!args[0]?.public };
    if (expr.kind === "cast") return { constant: castConstant(args[0]?.constant, program.representationOf(expr.type!)) ?? undefined, public: !!args[0]?.public };
    if (expr.kind === "default") return { public: true };
    if (expr.kind === "tuple" || expr.kind === "struct" || expr.kind === "bytes") return { public: args.every(arg => arg.public) };
    const shieldedResult = observeShieldedSend && discardedBy && discardedBy !== "sequence-prefix" && expr.kind === "call"
      && owner && reachable.has(owner) ? returnedShieldedResult(program, expr, charge, depth + 1) : undefined;
    if (shieldedResult) {
      const minted = shieldedResult.target === "standard-library::mintShieldedToken";
      emit("discarded-shielded-send-result", expr.span,
        minted
          ? "The canonical shielded mint result is discarded by this source use. Review whether the caller needs the returned coin metadata; wallet or transaction machinery may retain metadata independently."
          : "The canonical shielded send result is discarded by this source use. Review whether the caller needs its sent or change metadata; wallet or transaction machinery may retain metadata independently.",
        { operation: shieldedResult.target.slice("standard-library::".length), discardedBy, evidence: "resolved-source-unused-api-result",
          entry: program.symbols.get(ctx.circuit)?.name ?? ctx.circuit,
          ...(shieldedResult.forwarders.length ? { producerTarget: shieldedResult.target,
            forwardedThrough: shieldedResult.forwarders.map(id => program.symbols.get(id)?.name ?? id) } : {}) });
    }
    // Calls and storage methods may introduce private native/witness values.
    return unknown();
  };
  // This is a discarded-result fact, not a proof of absent authentication.
  // Any non-alias use conservatively retains the result. Identity aliases retain
  // it only when some alias is used; this makes no general enforcement claim.
  const discardedVerifier = (expr: Expr) => returnedSchnorrVerifier(program,expr,charge);
  const reachable = new Set<string>(), pending = observeResults ? [...program.entries] : [];
  while (pending.length && charge()) {
    const id = pending.pop()!;
    if (reachable.has(id)) continue;
    reachable.add(id);
    for (const callee of program.functions.get(id)?.calls ?? []) {
      if (!charge()) break;
      if (!reachable.has(callee)) pending.push(callee);
    }
  }
  let owner: string | undefined;
  const reachedStatements = new Set<string>();
  const statement = (node: Statement, ctx: Context, depth = 0, continuation: readonly Statement[] = []): boolean => {
    if (!charge(depth)) return false;
    reachedStatements.add(spanId(node.span));
    if (node.kind === "block" || node.kind === "bindings") {
      const nested = node.kind === "bindings" ? ctx : copy(ctx); let stopped = false;
      for (const [index, child] of node.body.entries()) {
        if (stopped) { emit("dead-code", child.span, "Statement follows an unconditional return or constant-false assertion"); continue; }
        stopped = statement(child, nested, depth + 1, child.kind === "if" ? node.body.slice(index + 1, index + 9) : []);
      }
      // Binding scopes do not leak names; assignments invalidate outer values.
      for (const id of ctx.values.keys()) if (!nested.values.has(id)) ctx.values.delete(id);
      return stopped;
    }
    if (node.kind === "if") {
      const condition = expression(node.condition, ctx, depth + 1);
      if (condition.assertionFails) return true;
      const yes = copy(ctx), no = copy(ctx);
      yes.publicControl = no.publicControl = ctx.publicControl && condition.public;
      if (condition.constant?.kind === "boolean") {
        const truth = condition.constant.value === "true";
        emit("constant-condition", node.condition.span, `Condition is statically ${truth}`, { value: truth, evidence: "typed-source-constants" });
        const dead = truth ? node.otherwise : node.then;
        if (dead) emit("dead-code", dead.span, "Branch is excluded by a typed constant condition");
        const selected = truth ? node.then : node.otherwise;
        return selected ? statement(selected, ctx, depth + 1) : false;
      }
      const first = statement(node.then, yes, depth + 1), second = node.otherwise ? statement(node.otherwise, no, depth + 1) : false;
      const booleanBranch = redundantBooleanBranch(node, charge, depth + 1);
      if (booleanBranch) emit("redundant-boolean-branch", node.span,
        "Both arms contain only opposite Boolean literal returns. A direct return of the condition or its negation can express this source shape; preserve the condition's effects and disclosure boundary.",
        { evidence: "opposite-literal-only-return-arms", negated: booleanBranch.negated, measuredCost: "not-claimed" });
      for (const tail of first && second ? [] : duplicatedBranchTails(node, continuation, charge, depth + 1)) {
        if (!reachedStatements.has(spanId(tail.location)) || !reachedStatements.has(spanId(tail.returnLocation))) continue;
        emit("duplicated-branch-tail", tail.location,
          "A terminating branch repeats the same resolved expression statements and explicit return as its immediate following continuation. These operations lie on alternative routes, not a twice-executed history.",
          { evidence: "resolved-source-duplicated-terminating-tail", arm: tail.arm, statements: tail.statements, continuation: tail.continuation });
      }
      ctx.values.clear(); return first && second;
    }
    if (node.kind === "for") {
      const start = naturalValue(String(node.start)), end = naturalValue(String(node.end));
      if (!node.sequence && start !== undefined && end !== undefined && start >= end) { emit("dead-code", node.body.span, "Loop has an empty static iteration range"); return false; }
      const nested = copy(ctx); nested.values.clear();
      if (node.sequence) {
        const sequence = expression(node.sequence, ctx, depth + 1);
        if (sequence.assertionFails) return true;
        nested.publicControl &&= sequence.public;
      }
      bind(node.symbol, nested, unknown()); statement(node.body, nested, depth + 1); ctx.values.clear(); return false;
    }
    const discardedBy: Discard | undefined = node.kind === "expr" ? "expression-statement"
      : node.kind === "bind" && node.symbol && !retainedResults.has(node.symbol)
        ? resultUses?.hasAlias(node.symbol) ? "unused-alias-chain" : "unused-binding" : undefined;
    const value = expression(node.expr, ctx, depth + 1, discardedBy);
    const verifier = observeValidation ? discardedVerifier(node.expr) : undefined;
    if (verifier && owner && reachable.has(owner) && (node.kind === "expr"
      || node.kind === "bind" && node.symbol && !retainedResults.has(node.symbol))) {
      emit("ignored-validation-result", node.expr.span,
        "The Boolean outcome of the canonical jubjubSchnorrVerify is discarded. The call may impose internal constraints, but its signature-validity result does not constrain this caller through this use.",
        { verifier: "jubjubSchnorrVerify", discardedBy: node.kind === "expr" ? "expression-statement" : node.kind === "bind" && node.symbol && resultUses?.hasAlias(node.symbol) ? "unused-alias-chain" : "unused-binding", evidence: "resolved-source-unused-result",
          ...(verifier.forwarders.length ? { verifierTarget: verifier.target,
            forwardedThrough: verifier.forwarders.map(id=>program.symbols.get(id)?.name??id) } : {}) });
    }
    if (node.kind === "bind") { bind(node.symbol, ctx, value); if (node.pattern && node.pattern.kind !== "name") pattern(node.pattern, ctx, depth + 1); }
    return node.kind === "return" || value.assertionFails === true;
  };
  const visited = new Set<string>();
  const instances = new Map<string, SourceObservation[][]>();
  for (const fn of program.functions.values()) {
    if (!charge()) break;
    if (!fn.declaration.body || visited.has(fn.symbol.id)) continue;
    visited.add(fn.symbol.id);
    const firstObservation = observations.length;
    owner = fn.symbol.id;
    reachedStatements.clear();
    const ctx: Context = { values: new Map(), names: new Map(), circuit: fn.symbol.id, publicControl: true };
    for (const parameter of fn.declaration.parameters) { bind(parameter.symbol, ctx, unknown()); if (parameter.pattern) pattern(parameter.pattern, ctx, 0); }
    statement(fn.declaration.body, ctx);
    const site = spanId(fn.declaration.span), group = instances.get(site) ?? [];
    group.push(observations.splice(firstObservation)); instances.set(site, group);
  }
  // Physical source claims must hold in every instantiated copy. A generic
  // branch can be dead for one parameter value and live for another.
  const observationKey = (item: SourceObservation) => JSON.stringify([item.kind, spanId(item.location), item.message, item.metadata]);
  for (const group of instances.values()) {
    const common = new Map(group[0].map(item => [observationKey(item), item]));
    for (const items of group.slice(1)) {
      const keys = new Set(items.map(observationKey));
      for (const key of common.keys()) { if (!charge()) break; if (!keys.has(key)) common.delete(key); }
    }
    observations.push(...common.values());
  }
  const unique = new Map(observations.map(item => [JSON.stringify([item.kind, spanId(item.location)]), item]));
  return { complete, observations: complete ? [...unique.values()] : [], work };
}
