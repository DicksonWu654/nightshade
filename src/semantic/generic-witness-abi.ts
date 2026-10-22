import type { Expr, Span, Statement } from "../model.js";
import type { Program, SymbolInfo } from "./index.js";
import { numericBound, parseType, printType, sequenceLength } from "./types.js";

export const GENERIC_WITNESS_ABI_RULE = "generic-witness-maybe-abi";

export interface WitnessAbiSite {
  entry: string;
  caller: string;
  target: string;
  location: Span;
  kind: "call" | "callback";
}

export interface WitnessAbiSpecialization {
  symbol: string;
  resultType: string;
  parameters: string[];
  valueType: string;
  representation: "bigint" | "bytes";
  sites: WitnessAbiSite[];
}

export interface WitnessAbiConflict {
  template: string;
  location: Span;
  specializations: [WitnessAbiSpecialization, WitnessAbiSpecialization];
  entries: string[];
}

export type WitnessAbiResult = {
  complete: true; applicable: boolean; work: number; candidateEntries: string[]; conflicts: WitnessAbiConflict[];
} | {
  complete: false; applicable: true; work: number; reason: string; candidateEntries: string[]; conflicts: [];
};

/** Source/schema references, including dead branches and empty callbacks whose
 * wrappers are retained by 0.34.0. Neither successful invocation nor host failure
 * follows from a shared host method and disjoint required payload guards. */
export function genericWitnessAbi(program: Program, allowance = 20000,
  entries: readonly string[] = program.entries): WitnessAbiResult {
  let work = 0;
  const unavailable = (reason: string): never => { throw { witnessAbiUnavailable: reason }; };
  const charge = (amount = 1) => {
    work += amount;
    if (!Number.isSafeInteger(allowance) || allowance < 0 || work > allowance)
      unavailable("Generic witness ABI enumeration exhausted its bounded allowance");
  };
  // Bound parsing, alias expansion, field enumeration and the semantic comparison
  // of parameter types before invoking Program's ordinary type operations.
  const typeWork = (type: string, depth = 0): void => {
    charge(type.length + 1);
    if (depth > 32) unavailable("Generic witness ABI type enumeration exceeds its qualified depth");
    const nominal = program.nominalTypes.get(type);
    if (nominal) { typeWork(nominal.underlying, depth + 1); return; }
    let nesting = 0;
    for (const character of type) {
      if ("<[".includes(character) && ++nesting > 32) unavailable("Generic witness ABI type enumeration exceeds its qualified depth");
      if (">]".includes(character)) nesting--;
    }
    const term = parseType(type);
    for (const argument of term.args) typeWork(printType(argument), depth + 1);
    const fields = program.fieldsOf(type);
    if (fields) for (const field in fields) { charge(); typeWork(fields[field], depth + 1); }
  };
  const groups = new Map<string, Map<string, WitnessAbiSpecialization>>();
  const candidateEntries = new Set<string>();
  const observe = (symbol: SymbolInfo, site: WitnessAbiSite) => {
    if (!symbol.specializationOrigin) return; // Concrete witnesses are separate host declarations.
    typeWork(symbol.type);
    if (program.nativeTypeOf(symbol.type) !== "Maybe") return;
    candidateEntries.add(site.entry);
    if (program.compilerVersion !== "0.34.0" || program.zkirVersion !== 2)
      unavailable("Generic optional witness ABI wrappers are qualified only for compiler 0.34.0/ZKIR2");
    const origin = program.symbols.get(symbol.specializationOrigin);
    if (!origin || origin.kind !== "witness" || !origin.declaration?.generics)
      unavailable("A generic optional witness lacks its canonical template identity");
    if (!symbol.declaration) unavailable("A generic optional witness lacks its resolved signature");
    const existing = groups.get(origin!.id)?.get(symbol.id);
    if (existing) { existing.sites.push(site); return; }
    const valueType = program.fieldsOf(symbol.type)?.value;
    if (!valueType) unavailable("A canonical Maybe result lacks its resolved payload type");
    typeWork(valueType!);
    const representation = program.representationOf(valueType!);
    const term = parseType(representation);
    const host = representation === "Field" || term.name === "Uint" && numericBound(representation) !== undefined
      ? "bigint" : term.name === "Bytes" && sequenceLength(representation) !== undefined ? "bytes" : undefined;
    if (!host) unavailable("A generic optional witness payload has an unqualified host representation");
    const parameters: string[] = [];
    for (const parameter of symbol.declaration?.parameters ?? []) { charge(); typeWork(parameter.type); parameters.push(parameter.type); }
    const specializations = groups.get(origin!.id) ?? new Map<string, WitnessAbiSpecialization>();
    specializations.set(symbol.id, { symbol: symbol.id, resultType: symbol.type, parameters,
      valueType: valueType!, representation: host!, sites: [site] });
    groups.set(origin!.id, specializations);
  };
  try {
    const canonicalEntries = new Set<string>();
    for (const entry of program.entries) { charge(); canonicalEntries.add(entry); }
    for (const entry of entries) {
      charge();
      if (!canonicalEntries.has(entry)) unavailable("Generic witness ABI scan requires canonical entries");
      const pending = [entry], seen = new Set<string>();
      while (pending.length) {
        charge();
        const id = pending.pop()!;
        if (seen.has(id)) continue;
        seen.add(id);
        const symbol = program.symbols.get(id), fn = program.functions.get(id);
        if (!fn) {
          if (symbol?.kind === "intrinsic" || symbol?.kind === "witness") continue;
          unavailable("Generic witness ABI source reachability contains an unresolved callable");
        }
        if (!fn!.declaration.body) unavailable("Generic witness ABI source reachability lacks a resolved body");
        // CFG lowering drops zero-iteration loop bodies, but their witness ABI
        // wrappers are still emitted. Walk resolved owned statements instead.
        const pendingStatements: Statement[] = [fn!.declaration.body!];
        while (pendingStatements.length) {
          charge();
          const statement = pendingStatements.pop()!;
          const pendingExpressions: Expr[] = [];
          if (statement.kind === "block" || statement.kind === "bindings") {
            for (const child of statement.body) { charge(); pendingStatements.push(child); }
          } else if (statement.kind === "if") {
            pendingExpressions.push(statement.condition);
            pendingStatements.push(statement.then);
            if (statement.otherwise) pendingStatements.push(statement.otherwise);
          } else if (statement.kind === "for") {
            pendingStatements.push(statement.body);
            if (statement.sequence) pendingExpressions.push(statement.sequence);
          } else pendingExpressions.push(statement.expr);
          while (pendingExpressions.length) {
            charge();
            const expression = pendingExpressions.pop()!;
            if (expression.kind === "call" || expression.kind === "ref") {
              const target = expression.symbol && program.symbols.get(expression.symbol);
              if (expression.kind === "call" && !target) unavailable("Generic witness ABI scan found an unresolved call site");
              if (target && target.kind === "witness") observe(target, {
                entry, caller: id, target: target.id, location: expression.span,
                kind: expression.kind === "call" ? "call" : "callback" });
            }
            if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
            for (const argument of expression.args) { charge(); pendingExpressions.push(argument); }
          }
        }
        for (const callee of fn!.calls) { charge(); pending.push(callee); }
      }
    }
    const conflicts: WitnessAbiConflict[] = [];
    for (const [template, specializations] of groups) {
      charge();
      const values: WitnessAbiSpecialization[] = [];
      for (const value of specializations.values()) { charge(); values.push(value); }
      for (let first = 0; first < values.length; first++) for (let second = first + 1; second < values.length; second++) {
        charge();
        const left = values[first], right = values[second];
        if (left.representation === right.representation || left.parameters.length !== right.parameters.length) continue;
        let identical = true;
        for (let index = 0; index < left.parameters.length; index++) {
          charge(); typeWork(left.parameters[index]); typeWork(right.parameters[index]);
          if (!program.sameType(left.parameters[index], right.parameters[index])) { identical = false; break; }
        }
        if (!identical) continue;
        const reachable = new Set<string>();
        for (const specialization of [left, right]) for (const site of specialization.sites) { charge(); reachable.add(site.entry); }
        conflicts.push({ template, location: program.symbols.get(template)!.span,
          specializations: [left, right], entries: [...reachable] });
      }
    }
    return { complete: true, applicable: groups.size > 0, work, candidateEntries: [...candidateEntries], conflicts };
  } catch (error) {
    if (error && typeof error === "object" && "witnessAbiUnavailable" in error)
      return { complete: false, applicable: true, work, reason: String(error.witnessAbiUnavailable),
        candidateEntries: [...candidateEntries], conflicts: [] };
    throw error;
  }
}
