import type { Program } from "./index.js";
import type { Expr } from "../model.js";
import { parseType, printType } from "./types.js";

export const ZERO_DEFAULT_RULE = "zero-default-getter-membership-review";

/** Admission only. Charge every inspected edge/node and each retained reference
 * before allocation. Values are cumulative allocation units, not live heap size.
 * Getter/debit predicates preserve the original resolved source admission. */
export function zeroDefaultScope(program: Program, allowance = 20000, valueAllowance = 50000) {
  let work = 0, values = 0;
  const getters: string[] = [], spenders: string[] = [];
  const charge = (units = 1, retained = 0) => {
    work += units; values += retained;
    return work <= allowance && values <= valueAllowance;
  };
  const failed = (reason: "entries" | "work" | "values" | "unresolved") => ({ complete: false, work, values, reason, getters, spenders });
  const exhausted = () => failed(values > valueAllowance ? "values" : "work");
  if (!charge(0, 2)) return exhausted();
  if (program.entries.length > 64) return failed("entries");
  for (const entry of program.entries) {
    if (!charge()) return exhausted();
    const fn = program.functions.get(entry)!;
    if (fn.symbol.kind !== "circuit") continue;
    const numericGetter = /^(Field|Uint<\d+>)$/.test(program.representationOf(fn.declaration.type));
    if (!charge(0, 3)) return exhausted();
    const pending = [entry], seen = new Set<string>();
    let member = false, lookup = false, numericLookup = false, numericInsert = false, subtraction = false;
    while (pending.length) {
      if (!charge()) return exhausted();
      const id = pending.pop()!;
      if (seen.has(id)) continue;
      if (!charge(0, 1)) return exhausted();
      seen.add(id);
      const current = program.functions.get(id);
      if (!current) {
        const symbol = program.symbols.get(id);
        if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") return failed("unresolved");
        continue;
      }
      for (const node of current?.cfg.nodes ?? []) {
        if (!charge(1, 1)) return exhausted();
        const expressions: Expr[] = [];
        if (node.expr) {
          if (!charge(0, 1)) return exhausted();
          expressions.push(node.expr);
        }
        while (expressions.length) {
          if (!charge()) return exhausted();
          const expression = expressions.pop()!;
          if (expression.contractCall || expression.kind === "call" && (!expression.symbol || !program.symbols.has(expression.symbol))) return failed("unresolved");
          if (expression.kind === "binary" && expression.name === "-") subtraction = true;
          if (expression.kind === "member" && expression.value === "call") {
            member ||= expression.name === "member";
            lookup ||= expression.name === "lookup";
            if (expression.name === "lookup" || expression.name === "insert") {
              const type = parseType(program.representationOf(expression.args[0].inferredType ?? "unknown"));
              if (type.name === "Map" && type.args[1] && /^(Field|Uint<\d+>)$/.test(printType(type.args[1]))) {
                numericLookup ||= expression.name === "lookup";
                numericInsert ||= expression.name === "insert";
              }
            }
          }
          if (expression.kind === "lambda" && expression.symbol) {
            if (!charge(1, 1)) return exhausted();
            pending.push(expression.symbol);
          }
          for (const argument of expression.args) {
            if (!charge(1, 1)) return exhausted();
            expressions.push(argument);
          }
        }
      }
      for (const callee of current?.calls ?? []) {
        if (!charge(1, 1)) return exhausted();
        pending.push(callee);
      }
    }
    if (numericLookup && numericInsert && subtraction) {
      if (!charge(0, 1)) return exhausted();
      spenders.push(entry);
    }
    if (numericGetter && member && lookup) {
      if (!charge(0, 1)) return exhausted();
      getters.push(entry);
    }
  }
  return { complete: true, work, values, getters, spenders };
}
