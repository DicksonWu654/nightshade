import { Expr, Statement } from "../model.js";
import { Program } from "../semantic/index.js";
import { intrinsicModel } from "../semantic/intrinsics.js";
import { ownedVariables } from "./liveness.js";
import type { CFG, CFGNode } from "../cfg/index.js";

type CircuitEligibilityMode = "pure" | "read" | "mutation";

class LinearCircuitEligibility {
  private readonly eligible = new Map<string, boolean>();
  private readonly depths = new Map<string, number>();

  constructor(private readonly program: Program, private readonly mode: CircuitEligibilityMode = "pure") {}

  allows(id: string): boolean {
    if (this.eligible.has(id)) return this.eligible.get(id)!;
    this.eligible.set(id, false);
    const fn = this.program.functions.get(id);
    if (!fn || fn.emitsEvent || this.mode === "pure" && (fn.readsState.size || fn.writesState.size) || this.mode === "read" && fn.writesState.size) return false;
    const owned = ownedVariables(fn);
    const address = (expr: Expr): boolean => Boolean(expr.ledgerRoot) && expr.kind === "ref" && this.program.symbols.get(expr.symbol!)?.kind === "ledger";
    const expression = (expr: Expr): boolean => {
      if (expr.kind === "assign") return this.mode === "mutation" && expr.name === "=" && address(expr.args[0]) && expression(expr.args[1]);
      if (expr.kind === "member" && expr.value === "call") {
        const receiver = expr.args[0];
        const type = receiver.ledgerType ?? (receiver.kind === "ref" ? this.program.symbols.get(receiver.symbol!)?.type : receiver.inferredType);
        // Kernel context/effect observations must retain their ordered history.
        // Ordinary storage-summary replay does not yet record these operations.
        if (/^(Kernel|MerkleTree|HistoricMerkleTree)(?:<|$)/.test(this.program.representationOf(type ?? "unknown"))) return false;
        const effect = this.program.ledgerEffect(type ?? "unknown", expr.name!);
        if (effect?.coinArgument !== undefined) return false;
        if (this.mode === "mutation") return Boolean(effect?.writes && effect.result === "[]") && address(receiver) && expr.args.slice(1).every(expression);
        return this.mode === "read" && Boolean(effect?.reads && !effect.writes && !effect.region) && expression(receiver) && expr.args.slice(1).every(expression);
      }
      if (["assert", "conditional", "map", "fold", "lambda", "cast", "index", "slice"].includes(expr.kind)) return false;
      if (expr.kind === "binary" && (expr.checkedArithmetic || ["&&", "||"].includes(expr.name!) || expr.name === "-" && (expr.numericType ?? expr.inferredType) !== "Field")) return false;
      if (expr.kind === "ref") {
        const symbol = this.program.symbols.get(expr.symbol!);
        if (!symbol || symbol.kind === "ledger" && this.mode !== "read" || ["local", "parameter"].includes(symbol.kind) && !owned.has(symbol.id)) return false;
      }
      if (expr.kind === "member" && (expr.value === "call" || expr.ledgerRoot && this.mode !== "read")) return false;
      if (expr.kind === "call") {
        const symbol = this.program.symbols.get(expr.symbol!);
        if (!symbol || symbol.kind === "witness" || symbol.kind === "intrinsic" && intrinsicModel(symbol).kind === "witness") return false;
        if (symbol.kind === "intrinsic" && intrinsicModel(symbol).kind === "derived") return false;
        if (symbol.kind !== "intrinsic" && !this.allows(symbol.id)) return false;
      }
      return expr.args.every(expression);
    };
    const reachable = fn.cfg.reachableFrom(fn.cfg.entry);
    const result = fn.cfg.nodes.filter(node => reachable.has(node.id)).every(node => node.kind !== "branch" && (!node.expr || expression(node.expr)));
    this.eligible.set(id, result);
    return result;
  }

  completedCircuits(id: string): string[] {
    return this.completions(id).map(completion => completion.at(-1)!);
  }

  maximumDepth(id: string): number {
    const cached = this.depths.get(id);
    if (cached !== undefined) return cached;
    if (!this.allows(id)) return Infinity;
    const fn = this.program.functions.get(id)!;
    const reachable = fn.cfg.reachableFrom(fn.cfg.entry);
    const expression = (expr: Expr): number => Math.max(expr.kind === "call" && this.program.functions.has(expr.symbol!) ? this.maximumDepth(expr.symbol!) : 0, ...expr.args.map(expression));
    const depth = 1 + Math.max(0, ...fn.cfg.nodes.filter(node => reachable.has(node.id)).map(node => node.expr ? expression(node.expr) : 0));
    this.depths.set(id, depth);
    return depth;
  }

  completions(id: string): string[][] {
    const completed = new Set<string>();
    const paths: string[][] = [];
    const visit = (current: string, stack: string[]): void => {
      if (completed.has(current)) return;
      const fn = this.program.functions.get(current);
      if (!fn || !this.allows(current)) return;
      const expression = (expr: Expr): void => {
        expr.args.forEach(expression);
        if (expr.kind === "call") visit(expr.symbol!, [...stack, current]);
      };
      let position: number | undefined = fn.cfg.entry;
      while (position !== undefined) {
        const node: CFGNode = fn.cfg.nodes[position];
        if (node.expr) expression(node.expr);
        position = node.edges.find(edge => edge.target !== fn.cfg.abort)?.target;
      }
      completed.add(current);
      paths.push([...stack, current]);
    };
    visit(id, []);
    return paths;
  }
}

export class PureCircuitEligibility extends LinearCircuitEligibility {
  constructor(program: Program) { super(program); }
}

export class ReadCircuitEligibility extends LinearCircuitEligibility {
  constructor(program: Program) { super(program, "read"); }
}

export class MutationCircuitEligibility extends LinearCircuitEligibility {
  constructor(program: Program) { super(program, "mutation"); }
}

/** Structural admission only; this does not enable a cache or join alternatives. */
export interface BranchMutationGraphPlan {
  readonly branch: number;
  readonly conditionParameter: string;
  /** Actual CFG control lifetime; -1 can denote the synthetic postdominator. */
  readonly controlUntil: number;
  readonly convergence: number;
  readonly prefix: readonly number[];
  readonly whenTrue: readonly number[];
  readonly whenFalse: readonly number[];
  readonly suffix: readonly number[];
}
export interface BranchMutationPlan {
  readonly circuit: string;
  readonly assignments: number;
  readonly expressions: BranchMutationGraphPlan;
  readonly instructions: BranchMutationGraphPlan;
}

/**
 * A deliberately finite scalar helper subset. Every refusal means ordinary
 * interpretation remains necessary; it does not declare the source unsupported.
 */
export class BranchMutationEligibility {
  private readonly plans = new Map<string, BranchMutationPlan | undefined>();
  constructor(private readonly program: Program, private readonly maxWork = 4096) {
    if (!Number.isSafeInteger(maxWork) || maxWork < 1 || maxWork > 4096) throw new Error("Branch summary eligibility work must be in 1..4096");
  }
  allows(id: string): boolean { return this.plan(id) !== undefined; }
  plan(id: string): BranchMutationPlan | undefined {
    if (this.plans.has(id)) return this.plans.get(id);
    this.plans.set(id, undefined);
    const fn = this.program.functions.get(id);
    if (!fn || this.program.entries.includes(id) || fn.symbol.kind !== "circuit" || fn.declaration.type !== "[]" || !fn.declaration.body || fn.calls.size || fn.readsState.size || !fn.writesState.size) return undefined;
    let work = 0;
    const take = (): boolean => ++work <= this.maxWork;
    const scalar = (type: string | undefined): boolean => type === "Field" || type === "Boolean";
    const parameters = new Map<string, string>();
    for (const parameter of fn.declaration.parameters) {
      if (!take() || !parameter.symbol || !scalar(parameter.type)) return undefined;
      if (parameter.pattern && (parameter.pattern.kind !== "name" || parameter.pattern.symbol !== parameter.symbol || parameter.pattern.children.length)) return undefined;
      parameters.set(parameter.symbol, parameter.type);
    }
    const expressions = new Set<Expr>();
    const remember = (expr: Expr): boolean => {
      const pending = [expr];
      while (pending.length) {
        const current = pending.pop()!;
        if (!take()) return false;
        expressions.add(current);
        if (current.args.length + pending.length > this.maxWork - work) return false;
        pending.push(...current.args);
      }
      return true;
    };
    const value = (expr: Expr): boolean => {
      if (expr.kind === "disclose") return expr.args.length === 1 && atom(expr.args[0]);
      return atom(expr);
    };
    const atom = (expr: Expr): boolean => expr.args.length === 0 && (
      expr.kind === "ref" && parameters.has(expr.symbol!) ||
      expr.kind === "default" && scalar(expr.type ?? expr.inferredType) ||
      expr.kind === "literal" && scalar(expr.inferredType)
    );
    let assignments = 0;
    const assignment = (expr: Expr): boolean => {
      if (expr.kind !== "assign" || expr.name !== "=" || expr.args.length !== 2) return false;
      const target = expr.args[0], symbol = this.program.symbols.get(target.symbol!);
      if (target.kind !== "ref" || target.args.length || symbol?.kind !== "ledger" || target.ledgerRoot !== symbol.id || !scalar(symbol.type) || !value(expr.args[1])) return false;
      if (!remember(expr)) return false;
      assignments++; return true;
    };
    const flatten = (statement: Statement): Statement[] | undefined => {
      const pending = [statement], result: Statement[] = [];
      while (pending.length) {
        const current = pending.pop()!;
        if (!take()) return undefined;
        if (current.kind === "block") {
          if (current.body.length + pending.length > this.maxWork - work) return undefined;
          for (let index = current.body.length - 1; index >= 0; index--) pending.push(current.body[index]);
        } else result.push(current);
      }
      return result;
    };
    const body = flatten(fn.declaration.body);
    if (!body) return undefined;
    let condition: Expr | undefined;
    for (let index = 0; index < body.length; index++) {
      const statement = body[index];
      if (statement.kind === "expr") { if (!assignment(statement.expr)) return undefined; }
      else if (statement.kind === "return") {
        if (index !== body.length - 1 || statement.expr.kind !== "tuple" || statement.expr.args.length || !remember(statement.expr)) return undefined;
      } else if (statement.kind === "if") {
        const test = statement.condition;
        if (condition || test.kind !== "disclose" || test.args.length !== 1 || test.args[0].kind !== "ref" || parameters.get(test.args[0].symbol!) !== "Boolean" || !remember(test)) return undefined;
        condition = test;
        for (const arm of [statement.then, statement.otherwise]) {
          if (!arm) continue;
          const steps = flatten(arm);
          if (!steps || steps.some(step => step.kind !== "expr" || !assignment(step.expr))) return undefined;
        }
      } else return undefined;
    }
    if (!condition || !assignments) return undefined;
    const parameter = condition.args[0].symbol!;
    const graphPlan = (graph: CFG, instructions: boolean): BranchMutationGraphPlan | undefined => {
      if (graph.nodes.length > this.maxWork - work) return undefined;
      let branch: CFGNode | undefined;
      for (const node of graph.nodes) {
        if (!take() || node.binding || node.pattern || node.id < 0 || graph.nodes[node.id] !== node) return undefined;
        if (node.kind === "branch") { if (branch) return undefined; branch = node; }
        if (node.expr && (!expressions.has(node.expr) || instructions)) return undefined;
        if (node.instruction) {
          if (!instructions || !["evaluate", "copy"].includes(node.instruction.kind)) return undefined;
          if (node.instruction.kind === "evaluate" && !expressions.has(node.instruction.expression)) return undefined;
        }
        for (const edge of node.edges) if (!graph.nodes[edge.target]) return undefined;
      }
      if (!branch || branch.join === undefined || branch.join !== -1 && !graph.nodes[branch.join]) return undefined;
      if (!instructions && branch.expr !== condition || instructions && branch.instruction?.kind !== "copy") return undefined;
      const edges = branch.edges.filter(edge => edge.target !== graph.abort);
      if (edges.length !== 2 || edges[0].condition === edges[1].condition || edges.some(edge => typeof edge.condition !== "boolean")) return undefined;
      const route = (start: number, stop?: number): number[] | undefined => {
        const path: number[] = [], seen = new Set<number>();
        let current = start;
        while (current !== stop) {
          if (!take() || seen.has(current) || current === graph.abort) return undefined;
          seen.add(current); path.push(current);
          const node = graph.nodes[current];
          if (node.kind === "branch") return undefined;
          const next = node.edges.filter(edge => edge.target !== graph.abort);
          if (node.kind === "exit") return stop === undefined && next.length === 0 ? path : undefined;
          if (next.length !== 1) return undefined;
          current = next[0].target;
        }
        return path;
      };
      const prefix = route(graph.entry, branch.id), yes = route(edges.find(edge => edge.condition)!.target), no = route(edges.find(edge => !edge.condition)!.target);
      if (!prefix || !yes || !no) return undefined;
      const noNodes = new Set(no), convergence = yes.find(node => noNodes.has(node));
      if (convergence === undefined) return undefined;
      const suffix = yes.slice(yes.indexOf(convergence)), otherSuffix = no.slice(no.indexOf(convergence));
      if (suffix.length !== otherSuffix.length || suffix.some((node, index) => node !== otherSuffix[index])) return undefined;
      const whenTrue = yes.slice(0, yes.indexOf(convergence)), whenFalse = no.slice(0, no.indexOf(convergence));
      // Every non-abort node must belong to the proven finite diamond.
      const admitted = new Set([...prefix, branch.id, ...yes, ...no, graph.abort]);
      if (admitted.size !== graph.nodes.length) return undefined;
      return Object.freeze({ branch: branch.id, conditionParameter: parameter, controlUntil: branch.join, convergence,
        prefix: Object.freeze(prefix), whenTrue: Object.freeze(whenTrue), whenFalse: Object.freeze(whenFalse), suffix: Object.freeze(suffix) });
    };
    const reference = graphPlan(fn.cfg, false);
    if (!reference) return undefined;
    // This subset lowers to one tail per source CFG node and at most one
    // instruction per admitted expression. Reserve lowering plus inspection and
    // two route visits before requesting the lazy graph; refusal remains fallback.
    const loweredNodes = fn.cfg.nodes.length + expressions.size;
    if (loweredNodes * 4 > this.maxWork - work) return undefined;
    work += loweredNodes;
    const instruction = graphPlan(this.program.instructionCFG(id), true);
    if (!instruction) return undefined;
    const plan = Object.freeze({ circuit: id, assignments, expressions: reference, instructions: instruction });
    this.plans.set(id, plan);
    return plan;
  }
}
