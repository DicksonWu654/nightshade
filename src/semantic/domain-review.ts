import type { Program } from "./index.js";
import type { Region } from "../dataflow/regions.js";
import type { PrivateSource } from "../dataflow/index.js";

export const DOMAIN_REVIEW_RULE = "public-two-component-domain-review";

/** Canonical identities only; neither a source spelling nor a stored self value
 * elsewhere supplies preimage binding. */
export function canonicalSelfRead(region: Region, name: string): boolean {
  return region.root === "standard-library::kernel" && region.type === "standard-type::Kernel" && name === "self";
}

export function scalarEntryBytes(program: Program, entry: string, source: PrivateSource): boolean {
  return entryParameter(program, entry, source) && program.representationOf(program.symbols.get(source.symbol!)!.type) === "Bytes<32>";
}

export function entryParameter(program: Program, entry: string, source: PrivateSource): boolean {
  if (source.kind !== "entry-parameter" || !source.symbol) return false;
  const parameter = program.functions.get(entry)?.declaration.parameters.find(part => part.symbol === source.symbol);
  return !!parameter;
}

/** Preparation shares the observer's meter. Retain worklists and closure sets
 * only after charging; source references are borrowed, never serialized. */
export function domainReviewScope(program: Program, entry: string, allowance: (work: number, values: number) => boolean): boolean {
  const charge = (work: number, values: number) => {
    if (!allowance(work, values)) throw new Error("Domain review callable preparation exhausted its shared allowance");
  };
  charge(0, 3);
  const seen = new Set<string>(), pending = [entry];
  let applicable = false;
  while (pending.length) {
    charge(1, 0);
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    if (id === "intrinsic::persistentHash") applicable = true;
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness")
        throw new Error("Domain review callable closure is unresolved; structural absence is unavailable");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 1);
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(1, 0);
        const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol)))
          throw new Error("Domain review call target is unresolved; structural absence is unavailable");
        if (expr.symbol === "intrinsic::persistentHash") applicable = true;
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
        for (const arg of expr.args) { charge(1, 1); expressions.push(arg); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return applicable;
}
