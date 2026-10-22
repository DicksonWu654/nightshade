import { Expr, Pattern, Span, Statement, fail } from "../model.js";
import type { Instruction } from "../ir/index.js";

export interface CFGNode {
  id: number;
  kind: "entry" | "exit" | "abort" | "operation" | "branch" | "return";
  span: Span;
  expr?: Expr;
  instruction?: Instruction;
  binding?: string;
  pattern?: Pattern;
  join?: number;
  /** Truth of a short-circuit condition that evaluates its RHS. */
  booleanRhsTruth?: boolean;
  /** Conditional expression arms are identical total, effect-free values. */
  sameValueArms?: true;
  edges: { target: number; condition?: boolean }[];
}

export class CFG {
  readonly nodes: CFGNode[] = [];
  entry = 0;
  exit = 0;
  abort = 0;

  successors(node: number): number[] {
    return this.nodes[node]?.edges.map(edge => edge.target) ?? [];
  }

  predecessors(node: number): number[] {
    return this.nodes.filter(candidate => candidate.edges.some(edge => edge.target === node)).map(candidate => candidate.id);
  }

  reachableFrom(source: number): Set<number> {
    const visited = new Set<number>();
    const pending = this.nodes[source] ? [source] : [];
    while (pending.length) {
      const current = pending.pop()!;
      if (visited.has(current)) continue;
      visited.add(current);
      pending.push(...this.successors(current));
    }
    return visited;
  }

  dominators(): Map<number, Set<number>> {
    const reachable = this.reachableFrom(this.entry);
    const result = new Map([...reachable].map(node => [node, node === this.entry ? new Set([node]) : new Set(reachable)]));
    const incoming = new Map([...reachable].map(node => [node, this.predecessors(node).filter(parent => reachable.has(parent))]));
    let changed = true;
    while (changed) {
      changed = false;
      for (const node of reachable) {
        if (node === this.entry) continue;
        const parents = incoming.get(node)!;
        const intersection = new Set([...result.get(parents[0])!].filter(candidate => parents.every(parent => result.get(parent)!.has(candidate))));
        intersection.add(node);
        if (intersection.size !== result.get(node)!.size) { result.set(node, intersection); changed = true; }
      }
    }
    return result;
  }

  immediatePostdominators(): Map<number, number> {
    const predecessors = new Map(this.nodes.map(node => [node.id, [] as number[]]));
    for (const node of this.nodes) for (const edge of node.edges) predecessors.get(edge.target)!.push(node.id);
    const remaining = new Map(this.nodes.map(node => [node.id, node.edges.length]));
    const pending = this.nodes.filter(node => !node.edges.length).map(node => node.id);
    const parent = new Map<number, number>([[-1, -1]]);
    const depth = new Map<number, number>([[-1, 0]]);
    const commonAncestor = (first: number, second: number): number => {
      while (first !== second) {
        if (depth.get(first)! >= depth.get(second)!) first = parent.get(first)!;
        else second = parent.get(second)!;
      }
      return first;
    };
    while (pending.length) {
      const node = pending.pop()!;
      const successors = this.successors(node);
      const ancestor = successors.length ? successors.reduce(commonAncestor) : -1;
      parent.set(node, ancestor);
      depth.set(node, depth.get(ancestor)! + 1);
      for (const incoming of predecessors.get(node)!) {
        const count = remaining.get(incoming)! - 1;
        remaining.set(incoming, count);
        if (count === 0) pending.push(incoming);
      }
    }
    if (parent.size !== this.nodes.length + 1) throw new Error("Postdominator calculation requires an acyclic expanded CFG");
    parent.delete(-1);
    return parent;
  }

  isReachable(source: number, sink: number): boolean {
    if (!this.nodes[source] || !this.nodes[sink]) return false;
    const pending = [source];
    const visited = new Set<number>();
    while (pending.length) {
      const current = pending.pop()!;
      if (current === sink) return true;
      if (visited.has(current)) continue;
      visited.add(current);
      pending.push(...this.nodes[current].edges.map(edge => edge.target));
    }
    return false;
  }

  resolveAbortEdges(mayAbort: (expression: Expr) => boolean): void {
    for (const node of this.nodes) {
      if (node.expr && mayAbort(node.expr) && !node.edges.some(edge => edge.target === this.abort)) node.edges.push({ target: this.abort, condition: false });
    }
    const postdominators = this.immediatePostdominators();
    for (const node of this.nodes) {
      if (node.kind !== "branch") continue;
      const successors = node.edges.filter(edge => edge.target !== this.abort).map(edge => edge.target);
      node.join = successors.reduce((first, second) => {
        const ancestors = new Set([-1]);
        for (let current = first; current !== -1; current = postdominators.get(current)!) ancestors.add(current);
        while (!ancestors.has(second)) second = postdominators.get(second)!;
        return second;
      });
    }
  }
}

export function buildCFG(body: Statement, maxNodes = 10000): CFG {
  const cfg = new CFG();
  const add = (kind: CFGNode["kind"], span: Span, expr?: Expr, binding?: string): CFGNode => {
    if (cfg.nodes.length >= maxNodes) fail("cfg-budget", "CFG expansion budget exhausted", span);
    const node: CFGNode = { id: cfg.nodes.length, kind, span, expr, binding, edges: [] };
    cfg.nodes.push(node);
    return node;
  };
  const entry = add("entry", body.span);
  cfg.exit = add("exit", body.span).id;
  cfg.abort = add("abort", body.span).id;
  const compile = (statement: Statement, next: number, inLoop = false): number => {
    if (statement.kind === "block" || statement.kind === "bindings") {
      let continuation = next;
      for (const child of [...statement.body].reverse()) continuation = compile(child, continuation, inLoop);
      return continuation;
    }
    if (statement.kind === "if") {
      const node = add("branch", statement.span, statement.condition);
      node.join = next;
      node.edges.push({ target: compile(statement.then, next, inLoop), condition: true });
      node.edges.push({ target: statement.otherwise ? compile(statement.otherwise, next, inLoop) : next, condition: false });
      return node.id;
    }
    if (statement.kind === "for") {
      if (typeof statement.start !== "number" || typeof statement.end !== "number" || !Number.isSafeInteger(statement.start) || !Number.isSafeInteger(statement.end) || statement.end < statement.start || statement.end - statement.start > 256) fail("loop-budget", "Loop requires a finite specialized range of at most 256 iterations", statement.span);
      let continuation = next;
      for (let counter = statement.end - 1; counter >= statement.start; counter--) {
        const bodyEntry = compile(statement.body, continuation, true);
        const index: Expr = { kind: "literal", value: String(counter), args: [], span: statement.span, inferredType: `Uint<0..${BigInt(counter) + 1n}>` };
        const node = add("operation", statement.span, statement.sequence ? { kind: "index", args: [{ kind: "ref", name: "$sequence", symbol: statement.sequenceSymbol, args: [], span: statement.span }, index], span: statement.span } : index, statement.symbol);
        node.edges.push({ target: bodyEntry });
        continuation = node.id;
      }
      if (statement.sequence) {
        const sequence = add("operation", statement.span, statement.sequence, statement.sequenceSymbol);
        sequence.edges.push({ target: continuation });
        return sequence.id;
      }
      return continuation;
    }
    if (statement.kind === "return" && inLoop) fail("invalid-loop-return", "Compact does not permit returning out of a for loop", statement.span);
    const node = add(statement.kind === "return" ? "return" : "operation", statement.span, statement.expr, statement.kind === "bind" ? statement.symbol : undefined);
    if (statement.kind === "bind") node.pattern = statement.pattern;
    node.edges.push({ target: statement.kind === "return" ? cfg.exit : next });
    if (statement.expr.kind === "assert") node.edges.push({ target: cfg.abort, condition: false });
    return node.id;
  };
  entry.edges.push({ target: compile(body, cfg.exit) });
  const postdominators = cfg.immediatePostdominators();
  for (const node of cfg.nodes) if (node.kind === "branch") node.join = postdominators.get(node.id);
  return cfg;
}
