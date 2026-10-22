import type { Expr, Span, Statement } from "../model.js";
import { spanId } from "../model.js";
import type { Program } from "./index.js";
import { numericBound, parseType } from "./types.js";

export const DIGEST_NARROWING_RULE = "checked-digest-narrowing";
const HASHES = new Set(["intrinsic::persistentHash", "intrinsic::keccak256"]);
interface Digest { kind: "digest"; primitive: string; hash: Span }
interface Narrowed { kind: "narrowed"; digest: Digest; cast: Span; targetType: string; maximum: string }
type Value = Digest | Narrowed;
export interface DigestNarrowingObservation {
  caller: string;
  entries: string[];
  primitive: string;
  hash: Span;
  cast: Span;
  targetType: string;
  maximum: string;
  uses: { kind: "ledger-write" | "exported-return"; location: Span }[];
}

/** A bounded source relationship, not a successful-history or failure proof.
 * Follow only unchanged canonical full digests, immutable local aliases, and
 * numeric-to-Bytes re-encoding after the checked cast. Source branches are not
 * joined; captures, computed/sliced digests, helper returns and ADT writes do
 * not acquire exact-origin certificates from merely sharing provenance. */
export function digestNarrowings(program: Program, allowance = 20000): {
  complete: boolean; observations: DigestNarrowingObservation[]; work: number;
} {
  let work = 0;
  class Exhausted extends Error {}
  const charge = (depth = 0): void => {
    if (++work > allowance || depth > 128) throw new Exhausted();
  };
  const chargeCopy = (size: number): void => { work += size; if (work > allowance) throw new Exhausted(); };
  const copyAliases = (aliases: Map<string, Value>): Map<string, Value> => { chargeCopy(aliases.size); return new Map(aliases); };
  try {
    charge();
    if (![...HASHES].some(id => program.symbols.has(id))) return { complete: true, observations: [], work };
    chargeCopy(program.entries.length);
    const entrySet = new Set(program.entries);
    const callers = new Map<string, Set<string>>();
    for (const entry of program.entries) {
      const pending = [entry], seen = new Set<string>();
      while (pending.length) {
        charge();
        const id = pending.pop()!;
        if (seen.has(id)) continue;
        seen.add(id);
        const entries = callers.get(id) ?? new Set<string>(); entries.add(entry); callers.set(id, entries);
        for (const callee of program.functions.get(id)?.calls ?? []) { charge(); pending.push(callee); }
      }
    }
    const observations: DigestNarrowingObservation[] = [];
    for (const [caller, entries] of callers) {
      charge();
      const body = program.functions.get(caller)?.declaration.body;
      if (!body) continue;
      // A source alias certificate is deliberately immutable across the whole
      // body. In particular, a later assignment cannot leave a stale digest
      // origin on an earlier-declared local or projected byte update.
      const mutated = new Set<string>();
      const mutationExpression = (expr: Expr, depth: number): void => {
        charge(depth);
        if (expr.kind === "assign") {
          let target = expr.args[0];
          while (target && (target.kind === "member" || target.kind === "index")) { charge(depth); target = target.args[0]; }
          if (target?.kind === "ref" && target.symbol && program.symbols.get(target.symbol)?.kind === "local") mutated.add(target.symbol);
        }
        for (const arg of expr.args) mutationExpression(arg, depth + 1);
        if (expr.body) mutationStatement(expr.body, depth + 1);
      };
      const mutationStatement = (node: Statement, depth: number): void => {
        charge(depth);
        if (node.kind === "block" || node.kind === "bindings") for (const child of node.body) mutationStatement(child, depth + 1);
        else if (node.kind === "if") {
          mutationExpression(node.condition, depth + 1); mutationStatement(node.then, depth + 1);
          if (node.otherwise) mutationStatement(node.otherwise, depth + 1);
        } else if (node.kind === "for") {
          if (node.sequence) mutationExpression(node.sequence, depth + 1);
          mutationStatement(node.body, depth + 1);
        } else mutationExpression(node.expr, depth + 1);
      };
      mutationStatement(body, 0);
      const groups = new Map<string, { observation: DigestNarrowingObservation; uses: Set<string> }>();
      const record = (value: Value | undefined, kind: "ledger-write" | "exported-return", location: Span): void => {
        charge();
        if (value?.kind !== "narrowed") return;
        const key = spanId(value.cast);
        if (!groups.has(key)) chargeCopy(entries.size);
        const group = groups.get(key) ?? { observation: { caller, entries: [...entries], primitive: value.digest.primitive,
          hash: value.digest.hash, cast: value.cast, targetType: value.targetType, maximum: value.maximum, uses: [] }, uses: new Set<string>() };
        const useKey = `${kind}:${spanId(location)}`;
        if (!group.uses.has(useKey)) { group.uses.add(useKey); group.observation.uses.push({ kind, location }); }
        groups.set(key, group);
      };
      const expression = (expr: Expr, aliases: Map<string, Value>, depth: number): Value | undefined => {
        charge(depth);
        if (expr.kind === "ref") return expr.symbol && !mutated.has(expr.symbol) ? aliases.get(expr.symbol) : undefined;
        const values = expr.args.map(arg => expression(arg, aliases, depth + 1));
        // Anonymous bodies have their own resolved FunctionInfo and local
        // environment. Never project this function's aliases into a capture.
        if (expr.kind === "call" && HASHES.has(expr.symbol ?? "")
          && program.representationOf(expr.inferredType ?? "unknown") === "Bytes<32>")
          return { kind: "digest", primitive: expr.symbol!.slice("intrinsic::".length), hash: expr.span };
        if (expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") return values[0];
        if (expr.kind === "cast") {
          const target = program.representationOf(expr.type ?? "unknown"), bound = numericBound(target);
          if (values[0]?.kind === "digest" && bound !== undefined && bound < 1n << 256n
            && program.representationOf(expr.args[0].inferredType ?? "unknown") === "Bytes<32>")
            return { kind: "narrowed", digest: values[0], cast: expr.span, targetType: target, maximum: String(bound - 1n) };
          if (values[0]?.kind === "narrowed" && parseType(target).name === "Bytes"
            && numericBound(program.representationOf(expr.args[0].inferredType ?? "unknown")) !== undefined)
            return values[0];
        }
        if (expr.kind === "assign" && expr.name === "=" && expr.args[0]?.kind === "ref"
          && program.symbols.get(expr.args[0].symbol ?? "")?.kind === "ledger")
          record(values[1], "ledger-write", expr.span);
        return undefined;
      };
      const statement = (node: Statement, aliases: Map<string, Value>, depth: number): void => {
        charge(depth);
        if (node.kind === "block" || node.kind === "bindings") {
          const nested = node.kind === "bindings" ? aliases : copyAliases(aliases);
          for (const child of node.body) statement(child, nested, depth + 1);
        } else if (node.kind === "if") {
          expression(node.condition, aliases, depth + 1);
          statement(node.then, copyAliases(aliases), depth + 1);
          if (node.otherwise) statement(node.otherwise, copyAliases(aliases), depth + 1);
        } else if (node.kind === "for") {
          if (node.sequence) expression(node.sequence, aliases, depth + 1);
          statement(node.body, copyAliases(aliases), depth + 1);
        } else {
          const value = expression(node.expr, aliases, depth + 1);
          if (node.kind === "bind" && node.symbol && !mutated.has(node.symbol)
            && (!node.pattern || node.pattern.kind === "name") && value) aliases.set(node.symbol, value);
          if (node.kind === "return" && entrySet.has(caller)) record(value, "exported-return", node.span);
        }
      };
      statement(body, new Map(), 0);
      observations.push(...[...groups.values()].map(group => group.observation));
    }
    return { complete: true, observations, work };
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    return { complete: false, observations: [], work };
  }
}
