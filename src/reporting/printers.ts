import { Program } from "../semantic/index.js";

export type Printer = "cfg" | "ir" | "call-graph" | "state" | "entrypoints";

export const PRINTER_SCHEMA_VERSION = "nightshade-printer-1" as const;

export interface PrinterDocument {
  schemaVersion: typeof PRINTER_SCHEMA_VERSION;
  /** Compatibility discriminator retained for existing CLI consumers. */
  analysisKind: "structural-printer";
  printer: Printer;
  root: string;
  compilerVersion: string;
  zkirVersion: number;
  records: unknown;
}

export function printProgram(program: Program, printer: Printer): unknown {
  const functions = [...program.functions.values()].sort((left, right) => left.symbol.id.localeCompare(right.symbol.id));
  if (printer === "entrypoints") return program.entries.map(id => ({ id, name: program.symbols.get(id)!.name, location: program.symbols.get(id)!.span }));
  if (printer === "call-graph") return functions.map(fn => ({ id: fn.symbol.id, name: fn.symbol.name, calls: [...fn.calls].sort(), callers: program.findCallers(fn.symbol.id).map(caller => caller.symbol.id).sort() }));
  if (printer === "state") return functions.map(fn => ({ id: fn.symbol.id, name: fn.symbol.name, reads: [...fn.readsState].sort(), writes: [...fn.writesState].sort() }));
  if (printer === "ir") return functions.map(fn => {
    const graph = program.instructionCFG(fn.symbol.id);
    return { id: fn.symbol.id, name: fn.symbol.name, irVersion: "expression-effects-v1", entry: graph.entry, exit: graph.exit, abort: graph.abort, nodes: graph.nodes.map(node => ({ id: node.id, kind: node.kind, location: node.span, binding: node.binding, successors: node.edges, join: node.join, instruction: node.instruction ? { ...node.instruction, ...("expression" in node.instruction ? { expression: { ...node.instruction.expression, args: undefined, body: undefined, parameters: undefined } } : {}) } : undefined })) };
  });
  return functions.map(fn => ({ id: fn.symbol.id, name: fn.symbol.name, entry: fn.cfg.entry, exit: fn.cfg.exit, abort: fn.cfg.abort, nodes: fn.cfg.nodes.map(node => ({ id: node.id, kind: node.kind, location: node.span, expression: node.expr?.kind, binding: node.binding, successors: node.edges })) }));
}

/** Versioned envelope for structural printer output. */
export function printProgramDocument(program: Program, printer: Printer): PrinterDocument {
  return { schemaVersion: PRINTER_SCHEMA_VERSION, analysisKind: "structural-printer", printer, root: program.root,
    compilerVersion: program.compilerVersion, zkirVersion: program.zkirVersion,
    records: printProgram(program, printer) };
}
