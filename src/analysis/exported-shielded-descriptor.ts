import type { Expr, Pattern, Span, Statement } from "../model.js";
import { mayCallCircuits } from "../semantic/value-transfers.js";
import { parseType, sequenceLength, elementType, TUPLE_TYPE } from "../semantic/types.js";
import type { Program } from "../semantic/index.js";
import { shieldedDescriptorType, SHIELDED_DESCRIPTOR_PRODUCERS } from "../semantic/shielded-descriptor-targets.js";

interface Origin { location: Span; producer: string; field: string }
interface Value { origins: Origin[]; fields?: Record<string, Value>; items?: Value[]; unavailable?: boolean }
export interface ExportedDescriptorObservation { entry: string; location: Span; origins: Origin[] }
const empty = (): Value => ({ origins: [] });

/** Source routes, never successful-path evidence. Only represented immutable
 * values preserve descriptor identity; helpers use actual argument bindings. */
export function exportedShieldedDescriptors(program: Program, allowance = 20000) {
  let work = 0;
  const observations: ExportedDescriptorObservation[] = [], failures: { entry: string; reason: string }[] = [];
  class Unavailable extends Error {}
  const charge = (depth: number, amount = 1) => { work += amount; if (work > allowance || depth > 64) throw new Unavailable("Source provenance work/depth allowance exhausted"); };
  const all = (value: Value, depth = 0): Origin[] => { charge(depth); return [...value.origins, ...Object.values(value.fields ?? {}).flatMap(v => all(v, depth + 1)), ...(value.items ?? []).flatMap(v => all(v, depth + 1))]; };
  const lost = (value: Value, depth = 0): boolean => { charge(depth); return !!value.unavailable || Object.values(value.fields ?? {}).some(v => lost(v, depth + 1)) || (value.items ?? []).some(v => lost(v, depth + 1)); };
  const typed = (type: string, location: Span, producer: string, path = "", descriptor = false, depth = 0, seen = new Set<string>()): Value => {
    charge(depth);
    const canonical = program.representationOf(type);
    if (seen.has(canonical)) return empty();
    const next = new Set(seen); next.add(canonical);
    const term = parseType(type);
    if (["Vector", TUPLE_TYPE].includes(term.name)) {
      const length = sequenceLength(type);
      if (length === undefined || length > 256) {
        const element = typed(elementType(type), location, producer, path, descriptor, depth + 1, next);
        if (!all(element).length) return empty();
        throw new Unavailable("Relevant represented sequence exceeds descriptor layout allowance");
      }
      return { origins: [], items: Array.from({ length }, (_, index) => typed(elementType(type, index), location, producer, `${path}[${index}]`, descriptor, depth + 1, next)) };
    }
    const fields = program.fieldsOf(type);
    const coin = descriptor || shieldedDescriptorType(program, type);
    if (fields) return { origins: [], fields: Object.fromEntries(Object.entries(fields).map(([name, field]) => {
      charge(depth); return [name, typed(field, location, producer, path ? `${path}.${name}` : name, coin, depth + 1, next)];
    })) };
    return coin ? { origins: [{ location, producer, field: path }] } : empty();
  };
  const merge = (values: Value[], depth = 0): Value => {
    charge(depth, values.length + 1);
    if (values.length === 1) return values[0];
    const keys = new Set(values.flatMap(v => Object.keys(v.fields ?? {})));
    return { origins: values.flatMap(v => v.origins), unavailable: values.some(v => !!v.unavailable),
      fields: Object.fromEntries([...keys].map(key => [key, merge(values.map(v => v.fields?.[key] ?? empty()), depth + 1)])),
      items: Array.from({ length: Math.max(0, ...values.map(v => v.items?.length ?? 0)) }, (_, index) => merge(values.map(v => v.items?.[index] ?? empty()), depth + 1)) };
  };
  const targets = new Set(SHIELDED_DESCRIPTOR_PRODUCERS);
  let targetsReady = false;
  const applicable = (id: string): boolean => {
    if (!targetsReady) {
      for (const symbol of program.symbols.values()) {
        charge(0);
        if (symbol.kind === "witness" && all(typed(symbol.type, symbol.span, "external-descriptor-type")).length) targets.add(symbol.id);
      }
      targetsReady = true;
    }
    charge(0);
    const fn = program.functions.get(id);
    if (!fn) return false;
    if (all(typed(fn.declaration.type, fn.declaration.span, "type-review")).length
      || fn.declaration.parameters.some(parameter => all(typed(parameter.type, parameter.span, "type-review")).length)) return true;
    const calls = mayCallCircuits(program, targets, Math.max(0, allowance - work), [id]);
    charge(0, calls.work);
    if (!calls.complete) throw new Unavailable("Descriptor applicability call traversal exhausted its allowance");
    return calls.applicable;
  };
  for (const entry of program.entries) {
    try {
      charge(0);
      if (!applicable(entry)) continue;
      const functionBody = (id: string, args: Value[], stack: string[], depth: number): { value: Value; returns: { value: Value; location: Span }[] } => {
        charge(depth);
        if (stack.includes(id)) throw new Unavailable("Recursive forwarding has no descriptor provenance certificate");
        const fn = program.functions.get(id);
        if (!fn?.declaration.body) return { value: { ...merge(args), unavailable: args.some(v => all(v).length || lost(v)) }, returns: [] };
        const env = new Map<string, Value>();
        const bind = (pattern: Pattern, value: Value, level: number): void => {
          charge(level);
          if (pattern.kind === "name" && pattern.symbol) env.set(pattern.symbol, value);
          else if (pattern.kind !== "skip") pattern.children.forEach((child, index) => bind(child,
            pattern.kind === "struct" ? value.fields?.[pattern.fields![index]] ?? { origins: [], unavailable: lost(value) } : value.items?.[index] ?? { origins: [], unavailable: lost(value) }, level + 1));
        };
        for (const [index, parameter] of fn.declaration.parameters.entries()) {
          charge(depth);
          const value = args[index] ?? empty();
          if (parameter.symbol) env.set(parameter.symbol, value);
          if (parameter.pattern) bind(parameter.pattern, value, depth + 1);
        }
        const returns: { value: Value; location: Span }[] = [];
        const evaluate = (expr: Expr, level: number): Value => {
          charge(level);
          if (expr.kind === "ref") return expr.symbol && env.has(expr.symbol) ? env.get(expr.symbol)! : typed(expr.inferredType ?? "unknown", expr.span, "resolved-descriptor-reference");
          if (expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") return evaluate(expr.args[0], level + 1);
          if (expr.kind === "member" && expr.value !== "call") {
            const receiver = evaluate(expr.args[0], level + 1);
            return receiver.fields?.[expr.name!] ?? { origins: [], unavailable: lost(receiver) };
          }
          if (expr.kind === "lambda" && expr.body) {
            const relevantExpr = (e: Expr, d: number): boolean => {
              charge(d);
              return e.kind === "ref" && !!e.symbol && !!env.get(e.symbol) && (all(env.get(e.symbol)!).length > 0 || lost(env.get(e.symbol)!))
                || !!e.symbol && SHIELDED_DESCRIPTOR_PRODUCERS.has(e.symbol)
                || all(typed(e.inferredType ?? "unknown", e.span, "callback-type")).length > 0
                || e.args.some(arg => relevantExpr(arg, d + 1));
            };
            const relevantBody = (s: Statement, d: number): boolean => {
              charge(d);
              if (s.kind === "block" || s.kind === "bindings") return s.body.some(child => relevantBody(child, d + 1));
              if (s.kind === "if") return relevantExpr(s.condition, d + 1) || relevantBody(s.then, d + 1) || !!s.otherwise && relevantBody(s.otherwise, d + 1);
              if (s.kind === "for") return !!s.sequence && relevantExpr(s.sequence, d + 1) || relevantBody(s.body, d + 1);
              return relevantExpr(s.expr, d + 1);
            };
            return { origins: [], unavailable: relevantBody(expr.body, level + 1) };
          }
          const values = expr.args.map(arg => evaluate(arg, level + 1));
          if (expr.kind === "call") {
            if (expr.symbol && SHIELDED_DESCRIPTOR_PRODUCERS.has(expr.symbol)) return typed(expr.inferredType ?? "unknown", expr.span, expr.symbol);
            // Hiding transformations deliberately end this unchanged-field route.
            if (expr.symbol && ["intrinsic::persistentHash", "intrinsic::transientHash", "intrinsic::persistentCommit", "intrinsic::transientCommit"].includes(expr.symbol)) return empty();
            if (expr.symbol?.startsWith("standard-library::") || expr.symbol?.startsWith("intrinsic::")) {
              if (!values.some(v => all(v).length || lost(v)) && !all(typed(expr.inferredType ?? "unknown", expr.span, "unknown-native-result")).length) return empty();
              return { origins: [], unavailable: true };
            }
            if (!expr.symbol) return { origins: [], unavailable: values.some(v => all(v).length || lost(v)) };
            if (!program.functions.get(expr.symbol)?.declaration.body && all(typed(expr.inferredType ?? "unknown", expr.span, "unknown-result")).length)
              return { origins: [], unavailable: true };
            if (!values.some(v => all(v).length || lost(v)) && !applicable(expr.symbol)) return empty();
            return functionBody(expr.symbol, values, [...stack, id], level + 1).value;
          }
          if (expr.kind === "struct") {
            const own = typed(expr.inferredType ?? expr.type ?? "unknown", expr.span, "canonical-descriptor-construction");
            if (all(own).length) return own;
            return { origins: [], fields: Object.fromEntries(values.map((value, index) => [expr.fields![index], value])) };
          }
          if (expr.kind === "default") return typed(expr.inferredType ?? expr.type ?? "unknown", expr.span, "canonical-descriptor-default");
          if (expr.kind === "tuple" || expr.kind === "bytes") return { origins: [], items: values };
          if (expr.kind === "index") {
            const index = expr.args[1]?.kind === "literal" ? Number(expr.args[1].value) : NaN;
            return Number.isSafeInteger(index) ? values[0].items?.[index] ?? { origins: [], unavailable: lost(values[0]) } : { origins: [], unavailable: all(values[0]).length > 0 || lost(values[0]) };
          }
          if (expr.kind === "conditional") return merge(values.slice(1));
          if (expr.kind === "sequence") return values.at(-1) ?? empty();
          if (["map", "fold", "lambda", "spread", "assign", "slice"].includes(expr.kind)) {
            if (values.some(v => all(v).length || lost(v)) || all(typed(expr.inferredType ?? "unknown", expr.span, "unsupported-result")).length) throw new Unavailable("Relevant callback, mutation or aggregate projection is outside the immutable descriptor route");
          }
          // Arithmetic, comparisons and representation-changing casts do not
          // certify unchanged descriptor fields. They are outside this contract.
          return empty();
        };
        const visit = (statement: Statement, level: number): void => {
          charge(level);
          if (statement.kind === "block" || statement.kind === "bindings") for (const child of statement.body) visit(child, level + 1);
          else if (statement.kind === "if") { evaluate(statement.condition, level + 1); visit(statement.then, level + 1); if (statement.otherwise) visit(statement.otherwise, level + 1); }
          else if (statement.kind === "for") throw new Unavailable("Loop forwarding is outside the descriptor source-route contract");
          else {
            const value = evaluate(statement.expr, level + 1);
            if (statement.kind === "bind") { if (statement.symbol) env.set(statement.symbol, value); if (statement.pattern) bind(statement.pattern, value, level + 1); }
            if (statement.kind === "return") returns.push({ value, location: statement.span });
          }
        };
        visit(fn.declaration.body, depth + 1);
        return { value: merge(returns.map(r => r.value)), returns };
      };
      const fn = program.functions.get(entry)!;
      const args = fn.declaration.parameters.map(parameter => typed(parameter.type, parameter.span, "entry-descriptor"));
      const result = functionBody(entry, args, [], 0);
      if (lost(result.value)) throw new Unavailable("Exported result has relevant unresolved descriptor provenance");
      for (const returned of result.returns) {
        const origins = all(returned.value);
        if (origins.length) observations.push({ entry, location: returned.location, origins });
      }
    } catch (error) {
      if (!(error instanceof Unavailable)) throw error;
      failures.push({ entry, reason: error.message });
    }
  }
  return { complete: !failures.length, observations: observations.filter(o => !failures.some(f => f.entry === o.entry)), failures, work };
}
