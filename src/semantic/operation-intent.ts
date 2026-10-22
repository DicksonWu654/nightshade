import { fail, type Span } from "../model.js";
import type { Program } from "./index.js";
import { naturalValue } from "./types.js";

export const OPERATION_INTENT_RULE = "operation-intent-policy";
export interface OperationIntentPolicy {
  circuit: string; ledgers: string[]; controllerCommitment: string; nonce: string;
  operation: string; version: string;
  statement: { self: string; operation: string; version: string; nonce: string };
  inputs: { field: string; parameter?: string; ledger?: string; writeValue?: string; context?: true }[];
}
export interface ResolvedOperationIntentPolicy extends Omit<OperationIntentPolicy, "inputs"> {
  inputs: { field: string; parameter?: string; ledger?: string; writeValue?: string; context?: true }[];
}

export function validateOperationIntent(value: unknown, location: Span, code = "invalid-policy"): OperationIntentPolicy[] {
  const reject = (message: string): never => fail(code, message, location);
  const object = (x: unknown, fields: string[]): Record<string, unknown> => {
    if (!x || typeof x !== "object" || Array.isArray(x) || Reflect.ownKeys(x).some(key => typeof key !== "string" || !fields.includes(key))) reject("Invalid operation-intent policy object");
    return x as Record<string, unknown>;
  };
  const dense = (x: unknown, min: number, max: number): unknown[] => {
    if (!Array.isArray(x) || x.length < min || x.length > max || Reflect.ownKeys(x).length !== x.length + 1) reject("Operation-intent policies require bounded dense arrays");
    return x as unknown[];
  };
  const text = (x: unknown): string => { if (typeof x !== "string" || !x.length) reject("Operation-intent selectors must be nonempty strings"); return x as string; };
  const fields = ["circuit", "ledgers", "controllerCommitment", "nonce", "operation", "version", "statement", "inputs"];
  return dense(value, 0, 64).map(raw => {
    const p = object(raw, fields);
    if (fields.some(field => !Object.hasOwn(p, field))) reject("Missing operation-intent policy field");
    const ledgers = dense(p.ledgers, 1, 16).map(text);
    if (new Set(ledgers).size !== ledgers.length) reject("Operation-intent protected Cells must be distinct");
    const operation = text(p.operation), version = text(p.version);
    if (operation.length > 80 || version.length > 80 || naturalValue(operation) === undefined || naturalValue(version) === undefined) reject("Operation-intent operation/version must be natural numeric strings");
    const statement = object(p.statement, ["self", "operation", "version", "nonce"]);
    const selectors = ["self", "operation", "version", "nonce"].map(field => text(statement[field]));
    const inputs = dense(p.inputs, 0, 16).map(rawInput => {
      const input = object(rawInput, ["field", "parameter", "ledger", "writeValue", "context"]);
      if (Object.hasOwn(input, "parameter") === Object.hasOwn(input, "ledger")) reject("Operation-intent input requires exactly one parameter or ledger selector");
      const field = text(input.field);
      if (input.context !== undefined && input.context !== true) reject("Operation-intent context must be true when present");
      if (input.parameter !== undefined && ((input.writeValue !== undefined) === (input.context === true))
        || input.ledger !== undefined && (input.writeValue !== undefined || input.context !== undefined))
        reject("Operation-intent parameter inputs require writeValue OR context:true; ledger inputs are entry snapshots");
      return { field, ...(input.parameter !== undefined ? { parameter: text(input.parameter), ...(input.context === true ? { context: true as const } : { writeValue: text(input.writeValue) }) } : { ledger: text(input.ledger) }) };
    });
    const all = [...selectors, ...inputs.map(input => input.field)];
    if (new Set(all).size !== all.length) reject("Operation-intent signed field selectors must be distinct");
    return { circuit: text(p.circuit), ledgers, controllerCommitment: text(p.controllerCommitment), nonce: text(p.nonce), operation, version,
      statement: { self: selectors[0], operation: selectors[1], version: selectors[2], nonce: selectors[3] }, inputs };
  });
}

export function resolveOperationIntent(program: Program, raw: unknown): ResolvedOperationIntentPolicy[] {
  const policies = validateOperationIntent(raw, program.rootSource.ast.span);
  const cell = (name: string) => {
    const found = program.activeSymbols().filter(symbol => symbol.kind === "ledger" && (symbol.id === name || symbol.name === name));
    if (found.length !== 1) fail("invalid-policy", `Operation-intent Cell ${name} resolves to ${found.length} symbols`, program.rootSource.ast.span);
    const symbol = found[0], type = program.representationOf(symbol.type);
    if (!/^(Boolean|Field|Uint<[0-9]+>|Bytes<[0-9]+>)$/.test(type)) fail("invalid-policy", "Operation-intent requires ordinary scalar Cells", symbol.span);
    return symbol;
  };
  const result = policies.map(p => {
    const found = program.activeSymbols().filter(symbol => symbol.kind === "circuit" && (symbol.id === p.circuit || symbol.name === p.circuit));
    if (found.length !== 1 || !program.entries.includes(found[0].id)) fail("invalid-policy", "Operation-intent circuit must resolve to one exported entry", program.rootSource.ast.span);
    const entry = found[0]; program.ensureFunction(entry.id);
    const commitment = cell(p.controllerCommitment), nonce = cell(p.nonce);
    if (program.representationOf(commitment.type) !== "Bytes<32>" || !/^Uint<[0-9]+>$/.test(program.representationOf(nonce.type))) fail("invalid-policy", "Operation-intent controller commitment requires Bytes<32> and nonce requires Uint", entry.span);
    const ledgers = p.ledgers.map(name => cell(name).id);
    if (new Set(ledgers).size !== ledgers.length || ledgers.includes(nonce.id) || ledgers.includes(commitment.id) || nonce.id === commitment.id) fail("invalid-policy", "Operation-intent protected Cells, nonce and commitment must be distinct", entry.span);
    return { ...p, circuit: entry.id, ledgers, nonce: nonce.id, controllerCommitment: commitment.id, inputs: p.inputs.map(input => {
      if (input.ledger) return { field: input.field, ledger: cell(input.ledger).id };
      const parameters = program.functions.get(entry.id)!.declaration.parameters.filter(parameter => parameter.symbol === input.parameter || parameter.name === input.parameter);
      if (parameters.length !== 1 || !parameters[0].symbol) fail("invalid-policy", "Operation-intent input parameter must resolve uniquely within its entry", entry.span);
      const symbol = program.symbols.get(parameters[0].symbol!)!;
      if (!/^(Boolean|Field|Uint<[0-9]+>|Bytes<[0-9]+>)$/.test(program.representationOf(symbol.type))) fail("invalid-policy", "Operation-intent inputs must be scalar", symbol.span);
      if (input.context) return { field: input.field, parameter: symbol.id, context: true as const };
      const writeValue = cell(input.writeValue!).id;
      if (!ledgers.includes(writeValue)) fail("invalid-policy", "Operation-intent writeValue must select a protected Cell", entry.span);
      return { field: input.field, parameter: symbol.id, writeValue };
    }) };
  });
  if (new Set(result.map(p => p.circuit)).size !== result.length) fail("invalid-policy", "Operation-intent entries must be declared once", program.rootSource.ast.span);
  for (let index = 0; index < result.length; index++) for (let other = 0; other < index; other++) {
    const a = result[index], b = result[other];
    if (a.nonce === b.nonce && a.controllerCommitment === b.controllerCommitment && BigInt(a.operation) === BigInt(b.operation))
      fail("invalid-policy", "Operation-intent entries sharing controller/nonce must have distinct operation tags", program.rootSource.ast.span);
  }
  return result;
}

/** Resolve complete callable closures before absence proofs; charge every visited edge/node. */
export function operationIntentClosure(program: Program, entry: string, charge: (work: number, values: number) => void): void {
  const seen = new Set<string>(), pending = [entry]; charge(0, 2);
  while (pending.length) {
    charge(1, 0); const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id); charge(0, 1);
    const fn = program.functions.get(id), symbol = program.symbols.get(id);
    if (!fn) {
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Operation-intent callable closure unresolved");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 0); const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(1, 0); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol))) throw new Error("Operation-intent call target unresolved");
        if (expr.kind === "lambda" && expr.symbol) { pending.push(expr.symbol); charge(0, 1); }
        for (const argument of expr.args) { expressions.push(argument); charge(1, 1); }
      }
    }
    for (const callee of fn.calls) { pending.push(callee); charge(1, 1); }
  }
}
