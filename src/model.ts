export interface Span {
  file: string;
  start: number;
  end: number;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface Diagnostic {
  /** Additional rule evidence, distinct from baseline analysis failure.
   * Root preparation failures use an empty entry sentinel only when the
   * compilation unit has no entrypoints; location.file identifies the root. */
  scope?: { kind: "rule"; detectorId: string; entry: string };
  code: string;
  message: string;
  location: Span;
}

/** The only non-error scan diagnostic: exact notice for a declared zero-entry root. */
export function isNoEntrypointsNotice(issue: Diagnostic, roots: readonly string[]): boolean {
  return issue.code === "no-entrypoints-analyzed"
    && issue.message === "No entrypoints analyzed; declaration checks completed."
    && !issue.scope && roots.includes(issue.location.file)
    && issue.location.start === 0 && issue.location.end === 0
    && issue.location.line === 1 && issue.location.column === 1
    && issue.location.endLine === 1 && issue.location.endColumn === 1;
}

export class AnalysisError extends Error {
  constructor(public readonly diagnostic: Diagnostic) {
    super(diagnostic.message);
  }
}

export interface Expr {
  kind: "literal" | "ref" | "call" | "member" | "index" | "binary" | "unary" |
    "cast" | "tuple" | "disclose" | "assert" | "assign" | "conditional" | "default" |
    "struct" | "spread" | "sequence" | "bytes" | "slice" | "lambda" | "map" | "fold" | "emit";
  span: Span;
  name?: string;
  value?: string;
  /** Parser attestation: assertion message is a literal, never an evaluated operand. */
  assertionMessageLiteral?: boolean;
  literalString?: string;
  paddingSize?: string;
  args: Expr[];
  type?: string;
  generics?: string;
  symbol?: string;
  inferredType?: string;
  numericType?: string;
  checkedArithmetic?: boolean;
  castKind?: "identity" | "numeric" | "scalar" | "bytes-to-sequence" | "sequence-to-bytes";
  fields?: string[];
  parameters?: Parameter[];
  body?: Statement;
  ledgerRoot?: string;
  /** Live storage type, distinct from the ordinary value read (e.g. Counter). */
  ledgerType?: string;
  event?: { name: string; version: number; tag: number };
  /** Resolved call through a declared external-contract interface. Its callee
   * effects are not modeled; any entry that reaches it is incomplete. */
  contractCall?: { contract: string; circuit: string };
}

export interface Pattern {
  kind: "name" | "tuple" | "struct" | "skip";
  name?: string;
  fields?: string[];
  children: Pattern[];
  span: Span;
  symbol?: string;
}

export type Statement =
  | { kind: "block"; span: Span; body: Statement[] }
  | { kind: "bind"; span: Span; name: string; type?: string; expr: Expr; symbol?: string; pattern?: Pattern }
  | { kind: "bindings"; span: Span; body: Statement[] }
  | { kind: "expr" | "return"; span: Span; expr: Expr }
  | { kind: "if"; span: Span; condition: Expr; then: Statement; otherwise?: Statement }
  | { kind: "for"; span: Span; name: string; start: number | string; end: number | string; sequence?: Expr; sequenceSymbol?: string; body: Statement; symbol?: string };

export interface Parameter {
  name: string;
  type: string;
  inferred?: boolean;
  span: Span;
  symbol?: string;
  pattern?: Pattern;
}

export interface Declaration {
  order?: number;
  kind: "circuit" | "witness" | "constructor" | "ledger" | "module" | "type";
  name: string;
  span: Span;
  exported: boolean;
  type: string;
  generics?: string;
  parameters: Parameter[];
  body?: Statement;
  scope?: ScopeAst;
  typeKind?: "struct" | "enum" | "alias" | "contract";
  variants?: string[];
  nominal?: boolean;
  sealed?: boolean;
  pure?: boolean;
  /** Circuit signatures of an external contract declaration (typeKind "contract"). */
  circuits?: Declaration[];
}

export interface ImportAst {
  order?: number;
  external?: boolean;
  name: string;
  prefix: string;
  selections?: { name: string; alias: string }[];
  generics?: string;
  span: Span;
}

export interface ScopeAst {
  declarations: Declaration[];
  imports: ImportAst[];
  exports: string[];
  pragmas: string[];
  includes?: { path: string; span: Span }[];
  span: Span;
}

export interface SourceFile {
  path: string;
  text: string;
  ast: ScopeAst;
  comments?: { text: string; span: Span }[];
}

export function spanId(span: Span): string {
  return `${span.file}:${span.start}`;
}

export function fail(code: string, message: string, location: Span): never {
  throw new AnalysisError({ code, message, location });
}

export function expressions(expr: Expr): Expr[] {
  return [expr, ...expr.args.flatMap(expressions)];
}
