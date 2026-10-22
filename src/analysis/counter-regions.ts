import type { CFG, CFGNode } from "../cfg/index.js";
import type { Diagnostic, Expr, Span, Statement } from "../model.js";
import type { Program } from "../semantic/index.js";
import { standardType } from "../semantic/intrinsics.js";
import { naturalValue } from "../semantic/types.js";

export interface CounterRegionLimits {
  maxSyntaxNodes?: number;
  /** Combined statement and instruction CFG nodes, including terminal nodes. */
  maxCFGNodes?: number;
  maxBranches?: number;
}

export interface CounterRegionWork { syntaxNodes: number; cfgNodes: number; branches: number }

export interface CounterMutationSite {
  node: number;
  normalSuccessor: number;
  /** The actual modeled abort edge is retained even for a constant operand. */
  abort: number;
}

export interface CounterDiamondSite {
  branch: number;
  trueEntry: number;
  normalContinuation: number;
  /** Actual CFG control expiry; -1 denotes the virtual exit, not the next diamond. */
  controlJoin: number;
  increment: CounterMutationSite;
}

export interface CounterRegionGraph {
  entry: number;
  exit: number;
  abort: number;
  reset?: CounterMutationSite;
  return?: number;
  diamonds: CounterDiamondSite[];
}

export interface TerminalCounterRegion {
  kind: "terminal-root-counter-increments";
  entry: string;
  ledger: string;
  location: Span;
  resetLocation?: Span;
  returnLocation?: Span;
  diamonds: {
    parameter: string;
    parameterIndex: number;
    amount: bigint;
    location: Span;
    conditionLocation: Span;
    incrementLocation: Span;
    amountLocation: Span;
  }[];
  graphs: { statements: CounterRegionGraph; instructions: CounterRegionGraph };
}

export type CounterRegionExtraction =
  | { status: "eligible"; region: TerminalCounterRegion; work: CounterRegionWork }
  | { status: "ineligible"; reason: string; location: Span; work: CounterRegionWork }
  | { status: "incomplete"; diagnostics: Diagnostic[]; work: CounterRegionWork };

const defaults = { maxSyntaxNodes: 4096, maxCFGNodes: 20000, maxBranches: 256 } as const;
class Refusal extends Error {
  constructor(readonly reason: string, readonly location: Span, readonly incomplete = false) { super(reason); }
}
const refuse = (reason: string, location: Span): never => { throw new Refusal(reason, location); };

/**
 * Eligibility only: no state transfer, successful-path claim or join is performed.
 * Unsupported shapes fall back to the exact engine. Exhaustion is a distinct
 * incomplete result and must not be mistaken for an eligible prefix.
 */
export function extractTerminalCounterRegion(program: Program, entry: string, options: CounterRegionLimits = {}): CounterRegionExtraction {
  if (!options || typeof options !== "object" || Array.isArray(options) || Object.keys(options).some(key => !Object.hasOwn(defaults, key))) throw new Error("Invalid Counter region limits");
  const limits = { ...defaults, ...options };
  for (const value of Object.values(limits)) if (!Number.isSafeInteger(value) || value < 1 || value > 1000000) throw new Error("Counter region limits must be integers in 1..1000000");
  const work: CounterRegionWork = { syntaxNodes: 0, cfgNodes: 0, branches: 0 };
  const budget = (field: keyof CounterRegionWork, maximum: number, location: Span, amount = 1): void => {
    if (amount > maximum - work[field]) throw new Refusal(`Counter region ${field} extraction budget exhausted`, location, true);
    work[field] += amount;
  };
  const syntax = (node: { span: Span }): void => budget("syntaxNodes", limits.maxSyntaxNodes, node.span);
  try {
    const fn = program.functions.get(entry);
    if (!fn || !program.entries.includes(entry) || fn.symbol.kind !== "circuit") return refuse("Requires a resolved circuit entrypoint", fn?.symbol.span ?? program.rootSource.ast.span);
    // Structural sequence compatibility also equates typed zero-length vectors
    // with []. Such exported result schemas are outside this void-only domain.
    if (fn.symbol.type !== "[]" || !fn.declaration.body) return refuse("Requires a void circuit body", fn.symbol.span);
    const parameters = new Map<string, number>();
    for (const [index, parameter] of fn.declaration.parameters.entries()) {
      syntax(parameter);
      if (!parameter.symbol || parameter.pattern && parameter.pattern.kind !== "name") return refuse("Parameter patterns are outside the Counter region", parameter.span);
      parameters.set(parameter.symbol, index);
    }
    // Visit one child at a time: even a wide rejected source cannot allocate an
    // unbounded pending list before the extraction budget is checked.
    function* statements(root: Statement): Generator<Statement> {
      const pending: Iterator<Statement>[] = [[root][Symbol.iterator]()];
      while (pending.length) {
        const next = pending.at(-1)!.next();
        if (next.done) { pending.pop(); continue; }
        syntax(next.value);
        if (next.value.kind === "block") pending.push(next.value.body[Symbol.iterator]());
        else yield next.value;
      }
    }
    let expressionNodes = 0;
    const expression = (expr: Expr): void => { syntax(expr); expressionNodes++; };
    let ledger: string | undefined;
    const mutation = (expr: Expr, operation: "increment" | "resetToDefault"): void => {
      expression(expr);
      if (expr.kind !== "member" || expr.value !== "call" || expr.name !== operation || expr.args.length !== (operation === "increment" ? 2 : 1)) return refuse("Requires a canonical root Counter mutation", expr.span);
      const receiver = expr.args[0];
      expression(receiver);
      const symbol = program.symbols.get(receiver.symbol ?? "");
      if (receiver.kind !== "ref" || receiver.args.length || !symbol || symbol.kind !== "ledger"
        || symbol.type !== standardType("Counter") || receiver.ledgerRoot !== symbol.id || expr.ledgerRoot !== symbol.id) return refuse("Mutation receiver is not a canonical root Counter ledger", receiver.span);
      const effect = program.ledgerEffect(symbol.type, operation);
      if (!effect?.writes || effect.reads || effect.region || effect.result !== "[]" || effect.arity !== expr.args.length - 1) return refuse("Unqualified Counter mutation effect", expr.span);
      if (ledger && ledger !== symbol.id) return refuse("Mixed Counter roots are outside the region", receiver.span);
      ledger = symbol.id;
    };
    const amount = (expr: Expr): bigint => {
      expression(expr);
      let literal = expr;
      if (expr.kind === "cast") {
        if (expr.args.length !== 1 || !program.sameType(expr.inferredType ?? "unknown", "Uint<16>") || !["identity", "numeric"].includes(expr.castKind ?? "")) return refuse("Only direct Uint16 literal casts are eligible", expr.span);
        literal = expr.args[0];
        expression(literal);
      }
      const value = literal.kind === "literal" && !literal.args.length ? naturalValue(literal.value ?? "") : undefined;
      if (value === undefined || value > 65535n) return refuse("Increment requires a literal in the Uint16 range", expr.span);
      return value;
    };
    const sourceDiamonds: { statement: Extract<Statement, { kind: "if" }>; increment: Expr; parameter: string; parameterIndex: number; amount: bigint }[] = [];
    const used = new Set<string>();
    let reset: Expr | undefined;
    let returned: Extract<Statement, { kind: "return" | "expr" }> | undefined;
    for (const statement of statements(fn.declaration.body)) {
      if (returned) return refuse("Effects or statements follow the void return", statement.span);
      if (statement.kind === "return") {
        expression(statement.expr);
        if (statement.expr.kind !== "tuple" || statement.expr.args.length) return refuse("Only an empty terminal return is eligible", statement.span);
        returned = statement;
        continue;
      }
      if (statement.kind === "expr" && !sourceDiamonds.length && !reset) {
        mutation(statement.expr, "resetToDefault");
        reset = statement.expr;
        continue;
      }
      if (statement.kind !== "if") return refuse("Requires sequential terminal Counter diamonds", statement.span);
      budget("branches", limits.maxBranches, statement.span);
      const condition = statement.condition;
      expression(condition);
      // disclose is an owned language operation, not a name-based callable test.
      if (condition.kind !== "disclose" || condition.args.length !== 1) return refuse("Branch requires built-in disclosure of a direct Boolean parameter", condition.span);
      const flag = condition.args[0];
      expression(flag);
      const symbol = program.symbols.get(flag.symbol ?? "");
      const parameterIndex = parameters.get(flag.symbol ?? "");
      if (flag.kind !== "ref" || flag.args.length || !symbol || symbol.kind !== "parameter" || parameterIndex === undefined || !program.sameType(symbol.type, "Boolean")) return refuse("Branch flag is not a direct Boolean entry parameter", flag.span);
      if (used.has(symbol.id)) return refuse("Reused branch parameters are outside the independent-choice region", flag.span);
      used.add(symbol.id);
      const trueArm = statements(statement.then);
      const first = trueArm.next();
      if (first.done || first.value.kind !== "expr") return refuse("True arm must contain one Counter increment", statement.then.span);
      mutation(first.value.expr, "increment");
      const value = amount(first.value.expr.args[1]);
      if (!trueArm.next().done) return refuse("True arm contains additional statements", statement.then.span);
      if (statement.otherwise && !statements(statement.otherwise).next().done) return refuse("False arm must be empty", statement.otherwise.span);
      sourceDiamonds.push({ statement, increment: first.value.expr, parameter: symbol.id, parameterIndex, amount: value });
    }
    if (!sourceDiamonds.length || !ledger) return refuse("Requires at least one Counter diamond", fn.symbol.span);
    if (fn.cfg.nodes.length !== 3 + sourceDiamonds.length * 2 + Number(Boolean(reset)) + Number(Boolean(returned))) return refuse("Statement CFG contains additional region operations", fn.symbol.span);
    // Accepted syntax lowers each expression to exactly one evaluate node. The
    // admission check occurs before lazy instruction lowering allocates a graph.
    budget("cfgNodes", limits.maxCFGNodes, fn.symbol.span, fn.cfg.nodes.length);
    budget("cfgNodes", limits.maxCFGNodes, fn.symbol.span, fn.cfg.nodes.length + expressionNodes);
    const instructions = program.instructionCFG(entry);
    if (instructions.nodes.length !== fn.cfg.nodes.length + expressionNodes) return refuse("Instruction lowering is outside the qualified Counter shape", fn.symbol.span);
    const graph = (cfg: CFG, instruction: boolean): CounterRegionGraph => {
      const byExpression = new Map<Expr, CFGNode>();
      const branches = new Map<Span, CFGNode>();
      const returns = new Map<Span, CFGNode>();
      for (const node of cfg.nodes) {
        const expr = instruction ? node.instruction?.kind === "evaluate" ? node.instruction.expression : undefined : node.expr;
        if (expr) {
          if (byExpression.has(expr)) return refuse("Expression maps to multiple CFG sites", expr.span);
          byExpression.set(expr, node);
        }
        if (node.kind === "branch") branches.set(node.span, node);
        if (node.kind === "return") returns.set(node.span, node);
      }
      const site = (expr: Expr): CounterMutationSite => {
        const node = byExpression.get(expr);
        const normal = node?.edges.filter(edge => edge.target !== cfg.abort);
        if (!node || node.kind !== "operation" || normal?.length !== 1 || node.edges.length !== 2 || !node.edges.some(edge => edge.target === cfg.abort)) return refuse("Counter mutation CFG must retain normal and abort edges", expr.span);
        return { node: node.id, normalSuccessor: normal[0].target, abort: cfg.abort };
      };
      const diamonds = sourceDiamonds.map(({ statement, increment }): CounterDiamondSite => {
        const node = branches.get(statement.span);
        const yes = node?.edges.find(edge => edge.condition === true);
        const no = node?.edges.find(edge => edge.condition === false);
        if (!node || !yes || !no || node.edges.length !== 2 || !instruction && node.expr !== statement.condition || node.join === undefined || node.join !== -1 && !cfg.nodes[node.join]) return refuse("Branch lacks a qualified CFG control join", statement.span);
        return { branch: node.id, trueEntry: yes.target, normalContinuation: no.target, controlJoin: node.join, increment: site(increment) };
      });
      const terminal = returned ? returns.get(returned.span) : undefined;
      if (returned && !terminal) return refuse("Void return lacks a CFG site", returned.span);
      const visited = new Set<number>();
      const expressionOrder = (expr: Expr): Expr[] => instruction ? [...expr.args.flatMap(expressionOrder), expr] : [expr];
      // Each admitted normal edge is visited once. Abort edges remain present;
      // they are not traversed as successful continuations or used as joins.
      const linear = (start: number, end: number, expected: Expr[]): void => {
        let current = start;
        let position = 0;
        while (current !== end) {
          const node = cfg.nodes[current];
          if (!node || visited.has(current) || !["entry", "operation", "return"].includes(node.kind)) return refuse("Counter CFG is not the qualified terminal diamond sequence", fn.symbol.span);
          visited.add(current);
          const expr = instruction ? node.instruction?.kind === "evaluate" ? node.instruction.expression : undefined : node.expr;
          if (expr && expr !== expected[position++]) return refuse("Counter CFG evaluation order differs from owned source", node.span);
          if (instruction && node.instruction && !["evaluate", "copy"].includes(node.instruction.kind)) return refuse("Counter CFG contains an unsupported instruction", node.span);
          const normal = node.edges.filter(edge => edge.target !== cfg.abort);
          if (normal.length !== 1) return refuse("Counter CFG continuation is not linear", node.span);
          current = normal[0].target;
        }
        if (position !== expected.length) return refuse("Counter CFG omits a source expression", fn.symbol.span);
      };
      linear(cfg.entry, diamonds[0].branch, [...(reset ? expressionOrder(reset) : []), ...(instruction ? expressionOrder(sourceDiamonds[0].statement.condition) : [])]);
      for (const [index, diamond] of diamonds.entries()) {
        visited.add(diamond.branch);
        linear(diamond.trueEntry, diamond.normalContinuation, expressionOrder(sourceDiamonds[index].increment));
        const next = diamonds[index + 1];
        linear(diamond.normalContinuation, next?.branch ?? cfg.exit,
          next ? instruction ? expressionOrder(sourceDiamonds[index + 1].statement.condition) : [] : returned ? expressionOrder(returned.expr) : []);
      }
      if (visited.size !== cfg.nodes.length - 2 || cfg.nodes[cfg.exit]?.edges.length || cfg.nodes[cfg.abort]?.edges.length) return refuse("Counter CFG contains extra or missing terminal nodes", fn.symbol.span);
      return { entry: cfg.entry, exit: cfg.exit, abort: cfg.abort, ...(reset ? { reset: site(reset) } : {}), ...(terminal ? { return: terminal.id } : {}), diamonds };
    };
    const graphs = { statements: graph(fn.cfg, false), instructions: graph(instructions, true) };
    return { status: "eligible", work, region: {
      kind: "terminal-root-counter-increments", entry, ledger, location: { ...fn.symbol.span },
      ...(reset ? { resetLocation: { ...reset.span } } : {}), ...(returned ? { returnLocation: { ...returned.span } } : {}),
      diamonds: sourceDiamonds.map(({ statement, increment, parameter, parameterIndex, amount }) => ({ parameter, parameterIndex, amount,
        location: { ...statement.span }, conditionLocation: { ...statement.condition.span }, incrementLocation: { ...increment.span }, amountLocation: { ...increment.args[1].span } })), graphs,
    } };
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    if (error.incomplete) return { status: "incomplete", work, diagnostics: [{ code: "counter-region-budget", message: error.reason, location: { ...error.location } }] };
    return { status: "ineligible", reason: error.reason, location: { ...error.location }, work };
  }
}
