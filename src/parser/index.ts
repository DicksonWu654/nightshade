import Parser from "tree-sitter-runtime";
import Compact, { grammarMetadata } from "./native.js";
import { Declaration, Expr, Parameter, Pattern, ScopeAst, SourceFile, Span, Statement, fail } from "../model.js";
import { normalizeLineEndings } from "../source-text.js";
import { decodeString } from "./strings.js";

type SyntaxNode = Parser.SyntaxNode;

export const GRAMMAR_REVISION = grammarMetadata.revision;
export const GRAMMAR_BUILD = grammarMetadata.identity;
const reservedIdentifiers = new Set("arguments await break case catch class continue debugger delete do emit eval event extends finally function in instanceof interface let null package private protected public static super switch this throw try typeof var void while with yield".split(" "));

export function parseSource(path: string, source: string): SourceFile {
  if (Buffer.byteLength(source) > 8 * 1024 * 1024) fail("source-budget", "Source exceeds the 8 MiB per-file limit", { file: path, start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 });
  const parser = new Parser();
  parser.setLanguage(Compact);
  parser.setTimeoutMicros(5000000);
  const adapter = new Adapter(path, source);
  const tree = parser.parse(adapter.text);
  if (!tree) fail("parser-budget", "Parser exceeded its five-second budget", { file: path, start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 });
  if (tree.rootNode.hasError) {
    const visit = (node: SyntaxNode): SyntaxNode | undefined => {
      if (node.type === "ERROR" || node.isMissing) return node;
      for (const child of node.children) {
        const error = visit(child);
        if (error) return error;
      }
      return undefined;
    };
    const error = visit(tree.rootNode) ?? tree.rootNode;
    fail("parse-error", "Syntax is invalid or unsupported by the pinned Compact grammar", adapter.span(error));
  }
  const pending = [tree.rootNode];
  const comments: NonNullable<SourceFile["comments"]> = [];
  while (pending.length) {
    const node = pending.pop()!;
    if (node.type === "comment") comments.push({ text: node.text, span: adapter.span(node) });
    if (["str", "file"].includes(node.type)) adapter.string(node);
    if (["id", "module_name", "function_name", "struct_name", "enum_name", "contract_name", "type_name", "tvar_name"].includes(node.type) && reservedIdentifiers.has(node.text)) fail("reserved-identifier", `${node.text} is reserved by Compact 0.26.0`, adapter.span(node));
    pending.push(...node.namedChildren);
  }
  return { path, text: source, ast: adapter.scope(tree.rootNode), comments: comments.sort((left, right) => left.span.start - right.span.start) };
}

class Adapter {
  private readonly offsets: Uint32Array;
  private readonly strings = new Map<number, string>();
  readonly text: string;

  constructor(private path: string, source: string) {
    this.text = normalizeLineEndings(source);
    this.offsets = new Uint32Array(this.text.length + 1);
    let byteOffset = 0;
    let charOffset = 0;
    for (let sourceIndex = 0; sourceIndex < source.length;) {
      const character = String.fromCodePoint(source.codePointAt(sourceIndex)!);
      this.offsets[charOffset] = byteOffset;
      if (character.length === 2) this.offsets[charOffset + 1] = byteOffset + 3;
      byteOffset += Buffer.byteLength(character);
      sourceIndex += character.length;
      if (character === "\r" && ["\n", "\u0085"].includes(source[sourceIndex])) {
        byteOffset += Buffer.byteLength(source[sourceIndex]);
        sourceIndex++;
      }
      charOffset += character.length;
      this.offsets[charOffset] = byteOffset;
    }
  }

  span(node: SyntaxNode): Span {
    return {
      file: this.path,
      start: this.offsets[node.startIndex],
      end: this.offsets[node.endIndex],
      line: node.startPosition.row + 1,
      column: node.startPosition.column + 1,
      endLine: node.endPosition.row + 1,
      endColumn: node.endPosition.column + 1,
    };
  }

  field(node: SyntaxNode, field: string): SyntaxNode {
    const value = node.childForFieldName(field);
    if (!value) fail("parser-adapter", `Missing ${field} on ${node.type}`, this.span(node));
    return value;
  }

  unsupported(node: SyntaxNode): never {
    return fail("unsupported-syntax", `Semantic adapter does not yet support ${node.type}`, this.span(node));
  }

  string(node: SyntaxNode): string {
    const cached = this.strings.get(node.startIndex);
    if (cached !== undefined) return cached;
    const value = decodeString(node.text, this.span(node));
    this.strings.set(node.startIndex, value);
    return value;
  }

  syntaxText(node: SyntaxNode): string {
    if (node.type === "comment") return "";
    if (["str", "file"].includes(node.type)) return JSON.stringify(this.string(node));
    return node.childCount ? node.children.map(child => this.syntaxText(child)).join("") : node.text;
  }

  fieldText(node: SyntaxNode, name: string): string | undefined {
    const field = node.childForFieldName(name);
    return field ? this.syntaxText(field) : undefined;
  }

  scope(node: SyntaxNode): ScopeAst {
    const scope: ScopeAst = { declarations: [], imports: [], exports: [], pragmas: [], includes: [], span: this.span(node) };
    for (const child of node.namedChildren) {
      const span = this.span(child);
      if (["comment", "module_name", "gparams", "export"].includes(child.type)) continue;
      if (child.type === "pragma") {
        scope.pragmas.push(child.text);
      } else if (child.type === "incld") {
        scope.includes!.push({ path: this.string(this.field(child, "file")), span });
      } else if (child.type === "idecl") {
        const rawName = this.field(child, "id").text;
        const external = ['"', "'"].includes(rawName[0]);
        const selection = child.childForFieldName("selection");
        const prefix = child.childForFieldName("prefix");
        scope.imports.push({
          name: external ? this.string(this.field(child, "id")) : rawName,
          external,
          prefix: prefix ? this.field(prefix, "id").text : "",
          selections: selection?.namedChildren.filter(item => item.type === "import_element").map(item => ({
            name: this.field(item, "id").text,
            alias: item.childForFieldName("alias")?.text ?? this.field(item, "id").text,
          })),
          generics: this.fieldText(child, "gargs"),
          span,
        });
      } else if (child.type === "xdecl") {
        scope.exports.push(...child.childrenForFieldName("id").map(item => item.text));
      } else if (["cdefn", "wdecl", "lconstructor", "ldecl", "mdefn", "struct", "enumdef", "type_alias_declaration", "ecdecl"].includes(child.type)) {
        const kind: Declaration["kind"] = child.type === "cdefn" ? "circuit" : child.type === "wdecl" ? "witness" :
          child.type === "lconstructor" ? "constructor" : child.type === "ldecl" ? "ledger" : child.type === "mdefn" ? "module" : "type";
        const name = child.childForFieldName("name") ?? child.childForFieldName("id");
        const body = child.childForFieldName("body");
        scope.declarations.push({
          kind, name: kind === "constructor" ? "constructor" : name?.text ?? this.unsupported(child), span,
          exported: Boolean(child.childForFieldName("export")),
          type: this.fieldText(child, "type") ?? "[]",
          generics: this.fieldText(child, "gparams"),
          parameters: child.namedChildren.filter(item => ["parg", "arg"].includes(item.type)).map(item => this.parameter(item)),
          body: body ? this.statement(body) : undefined,
          scope: kind === "module" ? this.scope(child) : undefined,
          typeKind: child.type === "struct" ? "struct" : child.type === "enumdef" ? "enum" : child.type === "ecdecl" ? "contract" : kind === "type" ? "alias" : undefined,
          variants: child.type === "enumdef" ? child.childrenForFieldName("id").map(item => item.text) : undefined,
          nominal: Boolean(child.childForFieldName("nominal")),
          sealed: Boolean(child.childForFieldName("sealed")),
          ...(child.childForFieldName("pure") ? { pure: true } : {}),
          // Declared external-contract interface: signatures only, never bodies.
          ...(child.type === "ecdecl" ? { circuits: child.childrenForFieldName("contract_circuit").map(circuit => ({
            kind: "circuit" as const, name: this.field(circuit, "id").text, span: this.span(circuit), exported: false, type: this.syntaxText(this.field(circuit, "type")),
            parameters: circuit.childrenForFieldName("arg").map(item => this.parameter(item)), ...(circuit.childForFieldName("pure") ? { pure: true } : {}) })) } : {}),
        });
      } else {
        this.unsupported(child);
      }
    }
    return scope;
  }

  parameter(node: SyntaxNode): Parameter {
    const pattern = node.childForFieldName("pattern");
    const name = pattern ? pattern.childForFieldName("id") : node.childForFieldName("id");
    return { name: name?.text ?? `$parameter${node.startIndex}`, type: this.syntaxText(this.field(node, "type")), span: this.span(node), pattern: pattern ? this.pattern(pattern) : undefined };
  }

  pattern(node: SyntaxNode): Pattern {
    const span = this.span(node);
    const name = node.childForFieldName("id");
    if (name) return { kind: "name", name: name.text, children: [], span };
    if (node.text.startsWith("[")) {
      const children: Pattern[] = [];
      let expecting = true;
      for (const child of node.children.slice(1, -1)) {
        if (child.type === ",") {
          if (expecting) children.push({ kind: "skip", children: [], span: this.span(child) });
          expecting = true;
        } else if (child.type === "pattern_tuple_elt") {
          children.push(this.pattern(child.namedChildren[0]));
          expecting = false;
        }
      }
      return { kind: "tuple", children, span };
    }
    if (node.text.startsWith("{")) {
      const fields = node.childrenForFieldName("pattern_struct_elt");
      return { kind: "struct", span, fields: fields.map(field => this.field(field, "id").text), children: fields.map(field => field.childForFieldName("pattern") ? this.pattern(this.field(field, "pattern")) : { kind: "name", name: this.field(field, "id").text, children: [], span: this.span(field) }) };
    }
    return this.unsupported(node);
  }

  statement(node: SyntaxNode): Statement {
    if (node.type === "stmt") return this.statement(node.namedChildren[0]);
    const span = this.span(node);
    if (node.type === "block") return { kind: "block", span, body: node.childrenForFieldName("stmt").map(item => this.statement(item)) };
    if (node.type === "const_stmt") {
      const bindings = node.namedChildren.filter(item => item.type === "cbinding");
      const body: Statement[] = bindings.map(binding => {
        const pattern = this.pattern(this.field(binding, "pattern"));
        return { kind: "bind", span: this.span(binding), name: pattern.name ?? `$binding${binding.startIndex}`, pattern, type: this.fieldText(binding, "type"), expr: this.expr(this.field(binding, "value")) };
      });
      return body.length === 1 ? body[0] : { kind: "bindings", span, body };
    }
    if (node.type === "return_stmt") return {
      kind: "return", span,
      expr: node.childForFieldName("value") ? this.expr(this.field(node, "value")) : { kind: "tuple", args: [], span },
    };
    if (node.type === "expression_sequence_stmt") return { kind: "expr", span, expr: this.expr(node.namedChildren[0]) };
    if (node.type === "if_stmt") return {
      kind: "if", span, condition: this.expr(this.field(node, "condition")),
      then: this.statement(this.field(node, "then_branch")),
      otherwise: node.childForFieldName("else_branch") ? this.statement(this.field(node, "else_branch")) : undefined,
    };
    if (node.type === "for_stmt") {
      const start = this.fieldText(node, "range_start");
      const end = this.fieldText(node, "range_end");
      return { kind: "for", span, name: this.field(node, "counter").text, start: start && /^\d+$/.test(start) && Number.isSafeInteger(Number(start)) ? Number(start) : start ?? 0, end: end && /^\d+$/.test(end) && Number.isSafeInteger(Number(end)) ? Number(end) : end ?? 0, sequence: node.childForFieldName("limit") ? this.expr(this.field(node, "limit")) : undefined, body: this.statement(this.field(node, "body")) };
    }
    return this.unsupported(node);
  }

  expr(node: SyntaxNode): Expr {
    const span = this.span(node);
    const build = (kind: Expr["kind"], args: Expr[] = [], extra: Partial<Expr> = {}): Expr => ({ kind, args, span, ...extra });
    const childExpr = (name: string): Expr => this.expr(this.field(node, name));
    if (["expr", "term", "expr_seq_term"].includes(node.type)) return this.expr(node.namedChildren[0]);
    if (node.type === "expr_seq") {
      const children = node.childrenForFieldName("expr");
      return children.length === 1 ? this.expr(children[0]) : build("sequence", children.map(child => this.expr(child)));
    }
    if (node.type === "id") return build("ref", [], { name: node.text });
    if (node.type === "lit" && node.namedChildCount) return this.expr(node.namedChildren[0]);
    if (["lit", "nat", "str", "pad"].includes(node.type)) return build("literal", [], { value: this.syntaxText(node), name: node.type, ...(node.type === "str" ? { literalString: this.string(node) } : node.type === "pad" ? { literalString: this.string(this.field(node, "str")), paddingSize: this.syntaxText(this.field(node, "nat")) } : {}) });
    if (node.type === "default_term") return build("default", [], { type: this.syntaxText(this.field(node, "type")) });
    if (node.type === "function_call_term") {
      const callee = this.field(node, "fun");
      const name = callee.childForFieldName("id");
      if (!name) return build("call", [this.function(callee), ...node.childrenForFieldName("expr").map(item => this.expr(item))], { name: "$anonymous" });
      return build("call", node.childrenForFieldName("expr").map(item => this.expr(item)), { name: name.text, generics: this.fieldText(callee, "gargs") });
    }
    if (node.type === "disclose_term") return build("disclose", [childExpr("expr")]);
    if (node.type === "emit_term") return build("emit", [childExpr("expr")]);
    if (node.type === "assert_term") return build("assert", [childExpr("condition")], { value: this.syntaxText(this.field(node, "message")), assertionMessageLiteral: this.field(node, "message").type === "str" });
    if (node.type === "cast_expr") return build("cast", [childExpr("expr")], { type: this.syntaxText(this.field(node, "type")) });
    if (node.type === "not_expr") return build("unary", [childExpr("expr")], { name: "!" });
    if (node.type === "conditional_expr") return build("conditional", [childExpr("condition"), childExpr("then_branch"), childExpr("else_branch")]);
    if (["or_expr", "and_expr", "comparison_expr", "rel_comparison_expr", "bin_sum_expr", "bin_mul_expr"].includes(node.type)) {
      return build("binary", [childExpr("left"), childExpr("right")], { name: node.childForFieldName("operator")?.text ?? (node.type === "or_expr" ? "||" : "&&") });
    }
    if (node.type === "assign_expr") return build("assign", [childExpr("target"), childExpr("value")], { name: this.field(node, "operator").text });
    if (node.type === "member_access_expr") {
      const isCall = node.children.some(item => item.text === "(");
      return build("member", [childExpr("base"), ...node.childrenForFieldName("expr").map(item => this.expr(item))], { name: this.field(node, "member").text, value: isCall ? "call" : "field" });
    }
    if (node.type === "index_access_expr") return build("index", [childExpr("base"), childExpr("index")]);
    if (["array_literal", "bytes_literal"].includes(node.type)) {
      return build(node.type === "bytes_literal" ? "bytes" : "tuple", node.namedChildren.filter(item => item.type !== "comment").map(item => this.expr(item)));
    }
    if (node.type === "spread_element") return build("spread", [childExpr("expr")]);
    if (node.type === "slice_term") return build("slice", [childExpr("value"), childExpr("index")], { value: this.syntaxText(this.field(node, "size")) });
    if (node.type === "struct_term") {
      const fields: string[] = [];
      const args: Expr[] = [];
      for (const child of node.namedChildren.filter(item => item.type === "struct_arg")) {
        const field = child.namedChildren[0];
        if (field.type === "struct_update_field") { fields.push("..."); args.push(this.expr(this.field(field, "expr"))); }
        else if (field.type === "struct_named_field_initializer") { fields.push(this.field(field, "id").text); args.push(this.expr(this.field(field, "expr"))); }
        else { fields.push(""); args.push(this.expr(field)); }
      }
      return build("struct", args, { type: this.syntaxText(this.field(node, "tref")), fields });
    }
    if (["map_term", "fold_term"].includes(node.type)) return build(node.type === "map_term" ? "map" : "fold", [this.function(this.field(node, "fun")), ...(node.childForFieldName("init_value") ? [childExpr("init_value")] : []), ...node.childrenForFieldName("expr").map(item => this.expr(item))]);
    return this.unsupported(node);
  }

  function(node: SyntaxNode): Expr {
    const span = this.span(node);
    const name = node.childForFieldName("id");
    if (name) return { kind: "ref", name: name.text, generics: this.fieldText(node, "gargs"), args: [], span };
    if (node.namedChildCount === 1 && node.namedChildren[0].type === "fun") return this.function(node.namedChildren[0]);
    const parameters = node.namedChildren.filter(item => ["pattern", "parg"].includes(item.type)).map(item => item.type === "parg" ? this.parameter(item) : { name: this.pattern(item).name ?? `$parameter${item.startIndex}`, pattern: this.pattern(item), type: "unknown", inferred: true, span: this.span(item) });
    const block = node.childForFieldName("block");
    const expr = node.childForFieldName("expr");
    if (!block && !expr) return this.unsupported(node);
    const resultType = node.childrenForFieldName("return").find(child => child.type === "type");
    return { kind: "lambda", name: `$lambda${node.startIndex}`, args: [], span, parameters, type: resultType ? this.syntaxText(resultType) : undefined, body: block ? this.statement(block) : { kind: "return", span: this.span(expr!), expr: this.expr(expr!) } };
  }
}
