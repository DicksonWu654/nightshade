import type { Program } from "./index.js";
import { persistentSchnorrKeyCell, schnorrVerifier } from "./signature-targets.js";
import type { PrivateSource } from "../dataflow/index.js";

export const STORED_ENROLLMENT_RULE = "stored-schnorr-key-enrollment-review";
export interface EnrollmentScope {
  cells: readonly string[];
  entries: readonly string[];
  writers: ReadonlyMap<string, readonly string[]>;
  uses: readonly string[];
  constructors: readonly string[];
}
export type EnrollmentCharge = (work?: number, values?: number) => boolean;

export function enrollmentParameter(program: Program, entry: string, source: PrivateSource, charge: EnrollmentCharge): boolean {
  if (source.kind !== "entry-parameter" || !source.symbol) return false;
  for (const parameter of program.functions.get(entry)!.declaration.parameters) {
    charge();
    if (parameter.symbol === source.symbol) return program.representationOf(parameter.type) === "JubjubPoint"
      || program.representationOf(parameter.type) === 'Opaque<"JubjubPoint">';
  }
  return false;
}

/** Complete resolved application closure; effects select every public writer,
 * including helpers/import instances. Runtime histories qualify survival. */
export function enrollmentReviewScope(program: Program, charge: EnrollmentCharge): EnrollmentScope {
  charge(0, 6);
  const cells: string[] = [], uses: string[] = [], constructors: string[] = [], entries: string[] = [];
  const writers = new Map<string, string[]>();
  for (const [id, symbol] of program.symbols) {
    charge();
    if (symbol.kind === "ledger" && persistentSchnorrKeyCell(program, id)) { charge(0, 3); cells.push(id); writers.set(id, []); }
  }
  for (const entry of program.entries) {
    charge(0, 3);
    const fn = program.functions.get(entry)!;
    if (fn.symbol.kind === "constructor") { charge(0, 1); constructors.push(entry); }
    let writes = false, verifies = false;
    for (const cell of cells) { charge(); if (fn.writesState.has(cell)) { charge(0, 1); writers.get(cell)!.push(entry); writes = true; } }
    const seen = new Set<string>(), pending = [entry];
    while (pending.length) {
      charge(); const id = pending.pop()!;
      if (seen.has(id)) continue;
      charge(0, 1); seen.add(id);
      verifies ||= schnorrVerifier(id);
      const target = program.functions.get(id), symbol = program.symbols.get(id);
      if (!target) {
        if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Enrollment callable closure is unresolved");
        continue;
      }
      for (const callee of target.calls) { charge(1, 1); pending.push(callee); }
    }
    if (verifies) { charge(0, 1); uses.push(entry); }
    if (writes || verifies || fn.symbol.kind === "constructor" && cells.length) { charge(0, 1); entries.push(entry); }
  }
  // Inspect every dependent body, including callbacks. No committed checkpoint
  // histories or external contract effects are qualified by this observer.
  charge(0, 2 + entries.length);
  const seen = new Set<string>(), pending = [...entries];
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    const fn = program.functions.get(id); if (!fn) continue;
    for (const node of fn.cfg.nodes) {
      charge(1, 1); const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && !expr.symbol) throw new Error("Enrollment effects include an unresolved external call");
        if (expr.kind === "member" && expr.name === "checkpoint"
          && program.representationOf(expr.args[0]?.inferredType ?? "") === "Kernel") throw new Error("Enrollment review does not qualify committed checkpoint histories");
        for (const argument of expr.args) { charge(1, 1); expressions.push(argument); }
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return { cells, entries, writers, uses, constructors };
}
