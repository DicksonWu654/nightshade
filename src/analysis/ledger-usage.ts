import type { Declaration, Expr, Parameter, Pattern, ScopeAst, Span, Statement } from "../model.js";
import { spanId } from "../model.js";
import type { Program, SymbolInfo } from "../semantic/index.js";
import { STANDARD_TYPE_MODELS } from "../semantic/intrinsics.js";
import { parseType } from "../semantic/types.js";

export interface WriteOnlyLedgerObservation {
  location: Span;
  name: string;
  /** Concrete canonical instances represented by this declaration. */
  instances: string[];
  writers: { circuit: string; location: Span }[];
}
export interface LedgerUsageResult {
  complete: boolean;
  work: number;
  observations: WriteOnlyLedgerObservation[];
  issues: { code: "ledger-usage-budget" | "ledger-usage-source-unavailable"; message: string; location: Span }[];
}

const cache = new WeakMap<Program, { functions: number; symbols: number; files: number; result: LedgerUsageResult }>();
/** No transfer/path observations are required. Lazy semantic bindings invalidate
 * this source-usage cache when the represented function/symbol/file set grows. */
export function cachedLedgerUsage(program: Program): LedgerUsageResult {
  const prior = cache.get(program);
  if (prior && prior.functions === program.functions.size && prior.symbols === program.symbols.size && prior.files === program.files.size) return prior.result;
  const result = ledgerUsage(program);
  cache.set(program, { functions: program.functions.size, symbols: program.symbols.size, files: program.files.size, result });
  return result;
}

/** Bounded source absence query. Semantic read/write sets include every resolved
 * body, helper and callback, regardless of entry reachability or path pruning.
 * Unbound bodies use defining-scope identities when available; spelling only
 * supplies conservative may-reads, including aliases and prefixed imports. ADTs are not
 * Cells and are deliberately outside this observation. */
export function ledgerUsage(program: Program, allowance = 200000): LedgerUsageResult {
  let work = 0, exhausted = false;
  const charge = (depth = 0): boolean => {
    if (++work > allowance || depth > 128) exhausted = true;
    return !exhausted;
  };
  const reads = new Set<string>(), writes = new Set<string>();
  const writers = new Map<string, { circuit: string; location: Span }[]>();
  for (const fn of program.functions.values()) {
    if (!charge()) break;
    for (const id of fn.readsState) { if (!charge()) break; reads.add(id); }
    for (const id of fn.writesState) {
      if (!charge()) break;
      writes.add(id);
      const sites = writers.get(id) ?? [];
      sites.push({ circuit: fn.symbol.id, location: fn.declaration.span });
      writers.set(id, sites);
    }
  }
  const groups = new Map<string, SymbolInfo[]>();
  // Template symbols do not denote concrete storage. Include every concrete
  // module instance, even when its circuits have not been lazily bound yet.
  for (const symbol of program.activeSymbols()) {
    if (!charge()) break;
    if (symbol.kind !== "ledger") continue;
    // representationOf normalizes resolved native identities to their standard
    // spelling; user declarations retain canonical qualified identities.
    const representation = parseType(program.representationOf(symbol.type)).name;
    if (STANDARD_TYPE_MODELS[representation]?.ledger) continue;
    const site = spanId(symbol.declaration?.span ?? symbol.span), group = groups.get(site) ?? [];
    group.push(symbol); groups.set(site, group);
  }
  const candidates: SymbolInfo[][] = [];
  for (const group of groups.values()) {
    let written = false, read = false;
    for (const symbol of group) { if (!charge()) break; written ||= writes.has(symbol.id); read ||= reads.has(symbol.id); }
    if (written && !read) candidates.push(group);
  }
  // Screening happens only for possible findings. Source uncertainty about an
  // already-read or never-written field does not invalidate this rule.
  const aliases = new Map(candidates.map(group => [spanId(group[0].declaration?.span ?? group[0].span), new Set([group[0].name])]));
  const imports: ScopeAst["imports"] = [], unresolved: { declaration: Declaration; owner: string }[] = [];
  const scopes = (scope: ScopeAst, depth = 0): void => {
    if (!charge(depth)) return;
    for (const imported of scope.imports) { if (!charge(depth + 1)) break; imports.push(imported); }
    for (const declaration of scope.declarations) {
      if (!charge(depth + 1)) break;
      if (declaration.scope) scopes(declaration.scope, depth + 1);
    }
  };
  if (candidates.length) for (const file of program.files.values()) scopes(file.ast);
  // Semantic declaration identities retain module-instance and include context.
  // A represented sibling's physical span cannot certify another instance's
  // unbound body. Templates also remain may-read evidence, never concrete state.
  if (candidates.length) for (const symbol of program.symbols.values()) {
    if (!charge()) break;
    if (symbol.declaration?.body && !program.functions.has(symbol.id)) unresolved.push({ declaration: symbol.declaration, owner: symbol.id });
  }
  // Alias closure is a may-view only. It can withhold an observation, never
  // supply equality or canonical identity. Prefix spellings need no expansion:
  // an unresolved name ending in a possible alias is conservatively screened.
  const possibleName = (reference: string, names: Iterable<string>): boolean => {
    for (const name of names) { if (!charge()) return false; if (reference.endsWith(name)) return true; }
    return false;
  };
  let changed = true;
  while (changed && !exhausted) {
    changed = false;
    for (const imported of imports) for (const selection of imported.selections ?? []) for (const names of aliases.values()) {
      if (!charge()) break;
      if (possibleName(selection.name, names) && !names.has(selection.alias)) {
        names.add(selection.alias); changed = true;
      }
    }
  }
  const unavailable = new Map<string, Span>();
  const patternNames = (pattern: Pattern, names: Set<string>, depth: number): void => {
    if (!charge(depth)) return;
    if (pattern.kind === "name" && pattern.name) names.add(pattern.name);
    for (const child of pattern.children) patternNames(child, names, depth + 1);
  };
  const parameterNames = (parameters: Parameter[], outer: ReadonlySet<string>, depth: number): Set<string> => {
    const names = new Set(outer);
    for (const parameter of parameters) {
      if (!charge(depth)) break;
      if (parameter.name) names.add(parameter.name);
      if (parameter.pattern) patternNames(parameter.pattern, names, depth + 1);
    }
    return names;
  };
  const referenceBinding = (expr: Expr, owner: string, depth: number, locals: ReadonlySet<string>): SymbolInfo | undefined =>
    expr.symbol ? program.symbols.get(expr.symbol) : expr.name && !locals.has(expr.name) ? program.lexicalBinding(owner, expr.name, () => charge(depth)) : undefined;
  const expression = (expr: Expr, depth: number, location: Span, owner: string, locals: ReadonlySet<string>): void => {
    if (!charge(depth)) return;
    // A whole Cell assignment/write target is not a value read. Only skip a
    // direct canonical ledger receiver; projections and unresolved targets stay
    // conservative. RHS and write operands still supply possible reads.
    if ((expr.kind === "assign" && expr.name === "="
      || expr.kind === "member" && expr.value === "call" && expr.name === "write")
      && expr.args[0]?.kind === "ref" && referenceBinding(expr.args[0], owner, depth + 1, locals)?.kind === "ledger") {
      charge(depth + 1);
      for (const child of expr.args.slice(1)) expression(child, depth + 1, location, owner, locals);
      return;
    }
    if (expr.kind === "ref" && expr.name && (expr.symbol || !locals.has(expr.name))) {
      const binding = referenceBinding(expr, owner, depth + 1, locals);
      if (binding?.kind === "ledger") {
        const site = spanId(binding.declaration?.span ?? binding.span);
        if (aliases.has(site)) unavailable.set(site, location);
      } else if (!binding) for (const [site, names] of aliases) {
        if (!charge(depth + 1)) break;
        if (possibleName(expr.name, names)) unavailable.set(site, location);
      }
    }
    for (const child of expr.args) expression(child, depth + 1, location, owner, locals);
    if (expr.body) statement(expr.body, depth + 1, location, owner, parameterNames(expr.parameters ?? [], locals, depth + 1));
  };
  const statement = (node: Statement, depth: number, location: Span, owner: string, locals: ReadonlySet<string>): void => {
    if (!charge(depth)) return;
    if (node.kind === "block" || node.kind === "bindings") {
      const names = new Set(locals);
      // Match the semantic block's local shadowing boundary, including patterns
      // and binding groups. Outer blocks never inherit a child's locals.
      for (const child of node.body) for (const binding of child.kind === "bindings" ? child.body : [child]) {
        if (!charge(depth + 1)) break;
        if (binding.kind === "bind") {
          if (binding.pattern) patternNames(binding.pattern, names, depth + 1);
          else names.add(binding.name);
        }
      }
      for (const child of node.body) statement(child, depth + 1, location, owner, names);
    }
    else if (node.kind === "if") {
      expression(node.condition, depth + 1, location, owner, locals); statement(node.then, depth + 1, location, owner, locals);
      if (node.otherwise) statement(node.otherwise, depth + 1, location, owner, locals);
    } else if (node.kind === "for") {
      if (node.sequence) expression(node.sequence, depth + 1, location, owner, locals);
      statement(node.body, depth + 1, location, owner, new Set([...locals, node.name]));
    } else expression(node.expr, depth + 1, location, owner, locals);
  };
  for (const { declaration, owner } of unresolved) statement(declaration.body!, 0, declaration.span, owner,
    parameterNames(declaration.parameters, program.lexicalNaturalParameters(owner, () => charge()), 0));
  let missing: SymbolInfo | undefined;
  if (candidates.length) for (const symbol of program.symbols.values()) {
    if (!charge()) break;
    if (symbol.kind === "circuit" && !symbol.declaration?.body) { missing = symbol; break; }
  }
  if (exhausted) return { complete: false, work, observations: [], issues: [{ code: "ledger-usage-budget",
    message: "Ledger source usage exceeded its work/depth allowance; no write-only absence result is available", location: program.rootSource.ast.span }] };
  if (missing && candidates.length) return { complete: false, work, observations: [], issues: [{ code: "ledger-usage-source-unavailable",
    message: `Circuit ${missing.name} has no modeled source body; ledger-read absence cannot be established`, location: missing.span }] };
  const observations: WriteOnlyLedgerObservation[] = [], issues: LedgerUsageResult["issues"] = [];
  for (const group of candidates) {
    const name = group[0].name, location = unavailable.get(spanId(group[0].declaration?.span ?? group[0].span));
    if (location) {
      issues.push({ code: "ledger-usage-source-unavailable", message: `Unresolved generic/module source may reference ledger ${name}; write-only absence is unavailable`, location });
      continue;
    }
    observations.push({ name, location: group[0].declaration?.span ?? group[0].span, instances: group.map(symbol => symbol.id),
      writers: [...new Map(group.flatMap(symbol => writers.get(symbol.id) ?? []).map(site => [site.circuit, site])).values()] });
  }
  return { complete: !issues.length, work, observations, issues };
}
