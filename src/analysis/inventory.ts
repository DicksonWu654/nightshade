import { createHash } from "node:crypto";
import type { Span } from "../model.js";
import type { Program, SymbolInfo } from "../semantic/index.js";
import { STANDARD_TYPE_MODELS, standardTypeName } from "../semantic/intrinsics.js";
import { FIELD_MODULUS, TUPLE_TYPE, naturalValue, numericBound, numericTypeError, parseType, printType } from "../semantic/types.js";

export interface InventoryOptions {
  /** Maximum nested signature shape depth, including nominal wrappers (default 16). */
  maxTypeDepth?: number;
  /** Shared budget for signature shape nodes and enum variants (default 4096). */
  maxTypeNodes?: number;
}

export type InventoryGapCode = "inventory-type-depth" | "inventory-type-budget" | "inventory-type-cycle" | "inventory-unsupported-type" | "inventory-unresolved-relation";

export interface InventoryGap {
  code: InventoryGapCode;
  message: string;
  owner: string;
  path: string;
  location: Span;
  type?: string;
}

/** `type` is the semantic canonical identity, not a source spelling or runtime ABI. */
export type InventoryType = { type: string } & (
  | { kind: "boolean" }
  | { kind: "field"; exclusiveUpperBound: string }
  | { kind: "uint"; exclusiveUpperBound: string }
  | { kind: "bytes"; length: string }
  | { kind: "vector"; length: string; element: InventoryType }
  | { kind: "tuple"; elements: InventoryType[] }
  | { kind: "enum"; declaration: string; location: Span; variants: { name: string; ordinal: string }[] }
  | { kind: "struct"; declaration: string; location?: Span; fields: { name: string; shape: InventoryType }[] }
  | { kind: "nominal"; declaration: string; location?: Span; underlying: InventoryType }
  | { kind: "unsupported"; reason: InventoryGapCode }
);

export interface InventoryIdentity {
  id: string;
  name: string;
  kind: SymbolInfo["kind"];
  location: Span;
}

export interface InventoryFunction extends InventoryIdentity {
  entrypoint: boolean;
  parameters: { name: string; location: Span; shape: InventoryType }[];
  result: InventoryType;
  /** Direct resolved calls; targets include external witnesses and modeled intrinsics. */
  calls: string[];
  /** Conservative ledger-symbol relations, propagated through resolved circuit calls. */
  reads: string[];
  writes: string[];
}

export interface AnalysisInventory {
  schemaVersion: "nightshade-analysis-inventory-1";
  semanticProfile: string;
  scope: "resolved-semantic-inventory";
  /** Applies only to inventory representation, never dataflow or compiler qualification. */
  status: "complete" | "incomplete";
  root: string;
  rootSource: string;
  sources: { id: string; sha256: string; location: Span }[];
  entrypoints: string[];
  functions: InventoryFunction[];
  callTargets: (InventoryIdentity & { implementation: "resolved-circuit" | "external-witness" | "modeled-intrinsic" | "unresolved" })[];
  ledgers: (InventoryIdentity & { type: string })[];
  gaps: InventoryGap[];
  budget: { maxTypeDepth: number; maxTypeNodes: number; expandedTypeNodes: number };
}

const identity = (symbol: SymbolInfo): InventoryIdentity => ({ id: symbol.id, name: symbol.name, kind: symbol.kind, location: { ...symbol.span } });
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;

/**
 * An offline semantic inventory of a successfully constructed Program. This does
 * not execute contracts, analyze paths, attest compiler acceptance, describe the
 * runtime ABI, or claim host/witness effects are modeled. Ledger types are opaque
 * canonical references; expanded shapes cover resolved function signatures only.
 * Identities retain Program's source/module paths and are checkout-dependent.
 */
export function buildAnalysisInventory(program: Program, options: InventoryOptions = {}): AnalysisInventory {
  if (!options || typeof options !== "object" || Array.isArray(options) || ![Object.prototype, null].includes(Object.getPrototypeOf(options))) throw new TypeError("Inventory options must be a plain object");
  for (const key of Reflect.ownKeys(options)) if (key !== "maxTypeDepth" && key !== "maxTypeNodes") throw new TypeError(`Unknown inventory option: ${String(key)}`);
  const maxTypeDepth = options.maxTypeDepth === undefined ? 16 : options.maxTypeDepth;
  const maxTypeNodes = options.maxTypeNodes === undefined ? 4096 : options.maxTypeNodes;
  if (!Number.isSafeInteger(maxTypeDepth) || maxTypeDepth < 0 || maxTypeDepth > 32) throw new RangeError("maxTypeDepth must be an integer between 0 and 32");
  if (!Number.isSafeInteger(maxTypeNodes) || maxTypeNodes < 1 || maxTypeNodes > 65536) throw new RangeError("maxTypeNodes must be an integer between 1 and 65536");
  const gaps: InventoryGap[] = [];
  let expandedTypeNodes = 0;
  interface Site { owner: string; path: string; location: Span }
  const unsupported = (type: string, site: Site, code: InventoryGapCode, message: string): InventoryType => {
    gaps.push({ code, message, ...site, location: { ...site.location }, type });
    return { kind: "unsupported", type, reason: code };
  };
  const shape = (type: string, site: Site, ancestors: Set<string> = new Set(), depth = 0): InventoryType => {
    if (ancestors.has(type)) return unsupported(type, site, "inventory-type-cycle", "Cyclic signature shape cannot be expanded");
    if (depth > maxTypeDepth) return unsupported(type, site, "inventory-type-depth", `Signature shape exceeds ${maxTypeDepth} nested levels`);
    if (expandedTypeNodes >= maxTypeNodes) return unsupported(type, site, "inventory-type-budget", `Signature shapes exceed ${maxTypeNodes} expansion nodes`);
    expandedTypeNodes++;
    const nested = new Set([...ancestors, type]);
    const child = (childType: string, path: string): InventoryType => shape(childType, { ...site, path: `${site.path}/${path}` }, nested, depth + 1);
    // Reject a wide subtree as a whole before allocating its child shapes. A
    // partially expanded aggregate must not look like its omitted fields are absent.
    const width = (count: number): InventoryType | undefined => count > maxTypeNodes - expandedTypeNodes
      ? unsupported(type, site, "inventory-type-budget", `Signature shape requires more than the remaining ${maxTypeNodes - expandedTypeNodes} expansion nodes`) : undefined;
    const nominal = program.nominalTypes.get(type);
    if (nominal) return {
      type, kind: "nominal", declaration: nominal.declaration,
      ...(program.symbols.get(nominal.declaration) ? { location: { ...program.symbols.get(nominal.declaration)!.span } } : {}),
      underlying: child(nominal.underlying, "underlying"),
    };
    const term = parseType(type);
    const error = numericTypeError(term);
    if (error) return unsupported(type, site, "inventory-unsupported-type", error);
    if (term.name === "Boolean" && !term.args.length) return { type, kind: "boolean" };
    if (term.name === "Field" && !term.args.length) return { type, kind: "field", exclusiveUpperBound: FIELD_MODULUS.toString() };
    const bound = numericBound(type);
    if (bound !== undefined) return { type, kind: "uint", exclusiveUpperBound: bound.toString() };
    if (term.name === "Bytes") return { type, kind: "bytes", length: naturalValue(term.args[0].name)!.toString() };
    if (term.name === "Vector") return { type, kind: "vector", length: naturalValue(term.args[0].name)!.toString(), element: child(printType(term.args[1]), "element") };
    if (term.name === TUPLE_TYPE) return width(term.args.length) ?? { type, kind: "tuple", elements: term.args.map((element, index) => child(printType(element), `${index}`)) };
    const native = standardTypeName(term.name);
    if (term.name === "Opaque" || native && STANDARD_TYPE_MODELS[native].ledger) return unsupported(type, site, "inventory-unsupported-type", "Opaque and ledger ADT runtime layouts are outside the signature inventory schema");
    const symbol = program.symbols.get(term.name);
    if (symbol?.declaration?.typeKind === "enum") {
      const variants = symbol.declaration.variants ?? [];
      const exhausted = width(variants.length);
      if (exhausted) return exhausted;
      expandedTypeNodes += variants.length;
      return {
        type, kind: "enum", declaration: symbol.id, location: { ...symbol.span },
        variants: variants.map((name, index) => ({ name, ordinal: `${index}` })),
      };
    }
    // fieldsOf consumes the semantic layer's resolved fields, including native
    // ordinary structures. Do not reinterpret declarations in the caller's scope.
    const fields = program.fieldsOf(type);
    if (fields) return width(Object.keys(fields).length) ?? {
      type, kind: "struct", declaration: symbol?.id ?? term.name,
      ...(symbol ? { location: { ...symbol.span } } : {}),
      fields: Object.entries(fields).map(([name, field]) => ({ name, shape: child(field, name) })),
    };
    return unsupported(type, site, "inventory-unsupported-type", "No supported resolved signature shape for this canonical type");
  };
  const relationGap = (owner: string, path: string, location: Span): void => {
    gaps.push({ code: "inventory-unresolved-relation", message: "Relation target is missing or lacks its expected semantic model", owner, path, location: { ...location } });
  };
  const functions = [...program.functions.values()].sort((a, b) => compare(a.symbol.id, b.symbol.id)).map(fn => {
    const owner = fn.symbol.id;
    for (const id of fn.calls) {
      const target = program.symbols.get(id);
      if (!target || !["circuit", "witness", "intrinsic"].includes(target.kind) || target.kind === "circuit" && !program.functions.has(id)) relationGap(owner, `calls/${id}`, fn.symbol.span);
    }
    for (const key of ["readsState", "writesState"] as const) for (const id of fn[key]) if (program.symbols.get(id)?.kind !== "ledger") relationGap(owner, `${key}/${id}`, fn.symbol.span);
    return {
      ...identity(fn.symbol), entrypoint: program.entries.includes(owner),
      parameters: fn.declaration.parameters.map((parameter, index) => ({ name: parameter.name, location: { ...parameter.span }, shape: shape(parameter.type, { owner, path: `parameters/${index}`, location: parameter.span }) })),
      result: shape(fn.declaration.type, { owner, path: "result", location: fn.declaration.span }),
      calls: [...fn.calls].sort(compare), reads: [...fn.readsState].sort(compare), writes: [...fn.writesState].sort(compare),
    };
  });
  for (const id of program.entries) if (!program.functions.has(id)) relationGap(id, "entrypoint", program.symbols.get(id)?.span ?? program.rootSource.ast.span);
  const callTargets = [...new Set(functions.flatMap(fn => fn.calls))].sort(compare).flatMap(id => {
    const target = program.symbols.get(id);
    if (!target) return [];
    const implementation = target.kind === "circuit" && program.functions.has(id) ? "resolved-circuit" : target.kind === "witness" ? "external-witness" : target.kind === "intrinsic" ? "modeled-intrinsic" : "unresolved";
    return [{ ...identity(target), implementation } as AnalysisInventory["callTargets"][number]];
  });
  gaps.sort((a, b) => compare(a.owner, b.owner) || compare(a.path, b.path) || compare(a.code, b.code));
  return {
    schemaVersion: "nightshade-analysis-inventory-1", semanticProfile: program.semanticProfile,
    scope: "resolved-semantic-inventory", status: gaps.length ? "incomplete" : "complete",
    root: program.root, rootSource: program.rootSource.path,
    sources: [...program.files].sort(([a], [b]) => compare(a, b)).map(([id, source]) => ({ id, sha256: createHash("sha256").update(source.text, "utf8").digest("hex"), location: { ...source.ast.span } })),
    entrypoints: [...program.entries].sort(compare), functions, callTargets,
    ledgers: program.activeSymbols().filter(symbol => symbol.kind === "ledger").sort((a, b) => compare(a.id, b.id)).map(symbol => ({ ...identity(symbol), type: symbol.type })),
    gaps, budget: { maxTypeDepth, maxTypeNodes, expandedTypeNodes },
  };
}
