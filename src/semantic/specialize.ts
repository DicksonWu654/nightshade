import { Declaration, Expr, ScopeAst, Span, Statement, fail } from "../model.js";
import { naturalValue, substituteType, typeArguments } from "./types.js";

export function genericBindings(parameters: string | undefined, argumentsText: string | undefined, location: Span): Map<string, string> {
  const names = typeArguments(parameters);
  const args = typeArguments(argumentsText);
  if (names.length !== args.length) fail("generic-arity", `Expected ${names.length} generic arguments, received ${args.length}`, location);
  const bindings = new Map<string, string>();
  names.forEach((name, index) => {
    const natural = name.startsWith("#");
    const value = naturalValue(args[index]);
    if (natural !== (value !== undefined)) fail("generic-kind", `Generic argument for ${name} must be ${natural ? "a natural number" : "a type"}`, location);
    bindings.set(name.replace(/^#\s*/, ""), value?.toString() ?? args[index]);
  });
  return bindings;
}

function shadow(bindings: Map<string, string>, parameters?: string): Map<string, string> {
  const result = new Map(bindings);
  for (const name of typeArguments(parameters)) result.delete(name.replace(/^#\s*/, ""));
  return result;
}

function expression(expr: Expr, bindings: Map<string, string>): void {
  if (expr.type) expr.type = substituteType(expr.type, bindings);
  if (expr.generics) expr.generics = substituteType(expr.generics, bindings);
  if (expr.kind === "ref" && bindings.has(expr.name!) && /^\d+$/.test(bindings.get(expr.name!)!)) {
    expr.kind = "literal";
    expr.value = bindings.get(expr.name!);
    expr.name = "nat";
  }
  if (expr.kind === "slice" && expr.value) expr.value = substituteType(expr.value, bindings);
  for (const arg of expr.args) expression(arg, bindings);
  for (const parameter of expr.parameters ?? []) parameter.type = substituteType(parameter.type, bindings);
  if (expr.body) statement(expr.body, bindings);
}

function statement(node: Statement, bindings: Map<string, string>): void {
  if (node.kind === "block" || node.kind === "bindings") for (const child of node.body) statement(child, bindings);
  else if (node.kind === "if") {
    expression(node.condition, bindings);
    statement(node.then, bindings);
    if (node.otherwise) statement(node.otherwise, bindings);
  } else if (node.kind === "for") {
    for (const key of ["start", "end"] as const) if (typeof node[key] === "string") {
      const replaced = substituteType(String(node[key]), bindings);
      node[key] = /^\d+$/.test(replaced) && Number.isSafeInteger(Number(replaced)) ? Number(replaced) : replaced;
    }
    if (node.sequence) expression(node.sequence, bindings);
    statement(node.body, bindings);
  } else {
    if (node.kind === "bind" && node.type) node.type = substituteType(node.type, bindings);
    expression(node.expr, bindings);
  }
}

export function specializeDeclaration(original: Declaration, bindings: Map<string, string>): Declaration {
  const result = structuredClone(original);
  result.generics = undefined;
  result.type = substituteType(result.type, bindings);
  for (const parameter of result.parameters) parameter.type = substituteType(parameter.type, bindings);
  if (result.body) statement(result.body, bindings);
  if (result.scope) result.scope = specializeScope(result.scope, bindings);
  return result;
}

export function specializeScope(original: ScopeAst, bindings: Map<string, string>): ScopeAst {
  const scope = structuredClone(original);
  for (const imported of scope.imports) if (imported.generics) imported.generics = substituteType(imported.generics, bindings);
  scope.declarations = scope.declarations.map(declaration => {
    const result = specializeDeclaration(declaration, shadow(bindings, declaration.generics));
    result.generics = declaration.generics;
    return result;
  });
  return scope;
}
