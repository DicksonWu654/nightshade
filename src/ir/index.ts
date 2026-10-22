import { CFG, CFGNode } from "../cfg/index.js";
import { Expr, Span, fail } from "../model.js";
import type { FunctionInfo, SymbolInfo } from "../semantic/index.js";
import { intrinsicModel, ledgerEffect } from "../semantic/intrinsics.js";
import { fieldModulus } from "../semantic/fields.js";
import { naturalValue, numericBound, sequenceLength } from "../semantic/types.js";
import { literalIndex } from "../semantic/sequences.js";
import { hashChoiceCandidate } from "../analysis/hash-choice.js";

type LedgerEffectResolver = (type: string, operation: string) => ReturnType<typeof ledgerEffect>;

export type Effect = "state-address" | "state-read" | "state-write" | "witness" | "call" | "constraint" | "disclosure-permission" | "event" | "may-abort";

export type Instruction =
  | { kind: "evaluate"; expression: Expr; inputs: string[]; result: string; effects: Effect[]; deferred?: true }
  | { kind: "copy"; inputs: [string]; result?: string; effects: Effect[] }
  | { kind: "merge"; inputs: string[]; predecessors: number[]; result: string; effects: Effect[] }
  | { kind: "logical"; expression: Expr; inputs: string[]; result: string; selected: boolean; effects: Effect[] };

export function operationEffects(expr: Expr, symbols: ReadonlyMap<string, SymbolInfo>, address = false, representationOf: (type: string) => string = type => type, resolveEffect: LedgerEffectResolver = (type, operation) => ledgerEffect(representationOf(type), operation)): Effect[] {
  if (expr.kind === "ref" && symbols.get(expr.symbol ?? "")?.kind === "ledger") return [address ? "state-address" : "state-read"];
  if (expr.kind === "assign") return ["state-write", "may-abort"];
  if (expr.kind === "assert") return ["constraint", "may-abort"];
  if (expr.kind === "disclose") return ["disclosure-permission"];
  if (expr.kind === "emit") return ["event"];
  // Representation-preserving and widening numeric casts cannot reject an
  // input. Invented abort edges keep short-circuit control alive beyond its
  // join and incorrectly make later effects depend on a total RHS.
  if (expr.kind === "cast") {
    if (expr.castKind === "identity") return [];
    if (expr.castKind === "numeric") {
      const source = representationOf(expr.args[0].inferredType ?? "unknown");
      const target = representationOf(expr.type ?? expr.inferredType ?? "unknown");
      const sourceBound = numericBound(source) ?? fieldModulus(source);
      const targetBound = numericBound(target) ?? fieldModulus(target);
      if (sourceBound !== undefined && targetBound !== undefined && sourceBound <= targetBound) return [];
    }
    return ["may-abort"];
  }
  if (expr.kind === "index" || expr.kind === "slice") {
    const length = sequenceLength(representationOf(expr.args[0].inferredType ?? "unknown"));
    const index = literalIndex(expr.args[1]);
    const bound = numericBound(representationOf(expr.args[1].inferredType ?? "unknown"));
    const size = expr.kind === "slice" ? naturalValue(expr.value ?? "") : 1n;
    if (length !== undefined && size !== undefined && (index !== undefined && index + size <= BigInt(length)
      || bound !== undefined && bound - 1n + size <= BigInt(length))) return [];
    return ["may-abort"];
  }
  if (expr.kind === "binary" && (expr.checkedArithmetic || expr.name === "-" && !fieldModulus(expr.numericType ?? expr.inferredType ?? "unknown"))) return ["may-abort"];
  if (expr.kind === "map" || expr.kind === "fold") {
    // Arguments are evaluated separately, even for an empty sequence. The
    // callback itself cannot execute then; an invented abort edge would keep
    // enclosing private control alive after its real join.
    const sequence = expr.args[expr.kind === "map" ? 1 : 2];
    if (sequenceLength(representationOf(sequence?.inferredType ?? "unknown")) === 0) return [];
    const target = symbols.get(expr.args[0].symbol ?? "");
    const witness = target?.kind === "witness" || target?.kind === "intrinsic" && intrinsicModel(target).kind === "witness";
    return ["call", ...(witness ? ["witness" as const] : []), "may-abort"];
  }
  if (expr.kind === "call") {
    const symbol = symbols.get(expr.symbol ?? "");
    if (symbol?.kind === "witness" || symbol?.kind === "intrinsic" && intrinsicModel(symbol).kind === "witness") return ["witness"];
    if (symbol?.kind === "intrinsic" && ["hash", "commitment", "constructor"].includes(intrinsicModel(symbol).kind)) return ["call"];
    return ["call", "may-abort"];
  }
  // External-contract callee effects are unmodeled; keep the call opaque and potentially aborting.
  if (expr.kind === "member" && expr.contractCall) return ["call", "may-abort"];
  if (expr.kind === "member" && expr.value === "field" && expr.ledgerRoot) return [address ? "state-address" : "state-read"];
  if (expr.kind === "member" && expr.value === "call" && expr.ledgerRoot) {
    const receiver = expr.args[0];
    const type = receiver.ledgerType ?? (receiver.kind === "ref" ? symbols.get(receiver.symbol ?? "")?.type : receiver.inferredType);
    const effect = resolveEffect(type ?? "unknown", expr.name!);
    return [...(effect?.reads ? ["state-read" as const] : []), ...(effect?.writes ? ["state-write" as const] : []), "may-abort"];
  }
  return [];
}

/** Bounded identity proof for two total, effect-free source arms. This does
 * not join histories or skip their evaluation. Calls, disclosures, constraints
 * and potentially rejecting expressions cannot establish this proof. */
export function sameTotalValueArms(expr: Expr, symbols: ReadonlyMap<string, SymbolInfo>, representationOf: (type: string) => string = type => type): boolean {
  if (expr.kind !== "conditional") return false;
  let work = 0;
  const key = (part: Expr, depth = 0): string | undefined => {
    if (++work > 128 || depth > 32) return undefined;
    if (!["literal", "default", "ref", "tuple", "struct", "bytes", "spread", "cast", "binary", "unary", "member", "index", "slice"].includes(part.kind)) return undefined;
    if (part.kind === "ref" && !["parameter", "local", "ledger"].includes(symbols.get(part.symbol!)?.kind ?? "")) return undefined;
    if (part.kind === "member" && part.value !== "field") return undefined;
    if (operationEffects(part, symbols, false, representationOf).some(effect => effect !== "state-read")) return undefined;
    const args = part.args.map(argument => key(argument, depth + 1));
    if (args.some(argument => argument === undefined)) return undefined;
    return JSON.stringify([part.kind, part.name, part.value, part.literalString, part.paddingSize, part.symbol,
      part.type ?? part.inferredType, part.fields, args]);
  };
  const left = key(expr.args[1]), right = key(expr.args[2]);
  return left !== undefined && left === right;
}

export function expressionAbortAnalysis(symbols: ReadonlyMap<string, SymbolInfo>, functions: ReadonlyMap<string, FunctionInfo>, representationOf: (type: string) => string = type => type, resolveEffect: LedgerEffectResolver = (type, operation) => ledgerEffect(representationOf(type), operation)): (expr: Expr) => boolean {
  const callAborts = new Map<string, boolean>();
  const mayAbort = (expr: Expr): boolean => {
    if (expr.args.some(mayAbort)) return true;
    if (expr.kind !== "call" || !functions.has(expr.symbol!)) return operationEffects(expr, symbols, false, representationOf, resolveEffect).includes("may-abort");
    if (callAborts.has(expr.symbol!)) return callAborts.get(expr.symbol!)!;
    callAborts.set(expr.symbol!, true);
    const callee = functions.get(expr.symbol!)!;
    const reachable = callee.cfg.reachableFrom(callee.cfg.entry);
    const result = callee.cfg.nodes.some(node => reachable.has(node.id) && node.expr && mayAbort(node.expr));
    callAborts.set(expr.symbol!, result);
    return result;
  };
  return mayAbort;
}

export function lowerInstructions(source: CFG, owner: string, symbols: ReadonlyMap<string, SymbolInfo>, maxNodes = 50000, functions: ReadonlyMap<string, FunctionInfo> = new Map(), representationOf: (type: string) => string = type => type, resolveEffect: LedgerEffectResolver = (type, operation) => ledgerEffect(representationOf(type), operation)): CFG {
  const cfg = new CFG();
  const mayAbort = expressionAbortAnalysis(symbols, functions, representationOf, resolveEffect);
  let nextValue = 0;
  const temporary = (): string => `$ir:${owner}:${nextValue++}`;
  const add = (kind: CFGNode["kind"], span: Span, instruction?: Instruction): CFGNode => {
    if (cfg.nodes.length >= maxNodes) fail("ir-budget", "Expression instruction budget exhausted", span);
    const node: CFGNode = { id: cfg.nodes.length, kind, span, instruction, edges: [] };
    cfg.nodes.push(node);
    return node;
  };
  const tails = new Map<number, CFGNode>();
  const starts = new Map<number, number>();
  const lower = (expr: Expr, result: string, next: number, address = false): number => {
    // Preserve a total hash choice as one evaluation site. The ordinary source
    // transfer still splits it whenever runtime admission declines compression.
    if (hashChoiceCandidate(expr, symbols)) {
      const allEffects = (part: Expr): Effect[] => [...operationEffects(part, symbols, false, representationOf, resolveEffect), ...part.args.flatMap(allEffects)];
      const effects = [...new Set(allEffects(expr))];
      const node = add("operation", expr.span, { kind: "evaluate", expression: expr, inputs: [], result, effects, deferred: true });
      node.edges.push({ target: next });
      if (effects.includes("may-abort")) node.edges.push({ target: cfg.abort, condition: false });
      return node.id;
    }
    if (expr.kind === "conditional" || expr.kind === "binary" && ["&&", "||"].includes(expr.name!)) {
      const condition = temporary();
      const branch = add("branch", expr.span, { kind: "copy", inputs: [condition], effects: [] });
      const merge: Instruction & { kind: "merge" } = { kind: "merge", inputs: [], predecessors: [], result, effects: [] };
      const join = add("operation", expr.span, merge);
      join.edges.push({ target: next });
      if (expr.kind === "conditional") {
        if (sameTotalValueArms(expr, symbols, representationOf)) branch.sameValueArms = true;
        for (const selected of [true, false]) {
          const arm = temporary();
          const selectedValue = temporary();
          const end = add("operation", expr.span, { kind: "copy", inputs: [arm], result: selectedValue, effects: [] });
          end.edges.push({ target: join.id });
          merge.inputs.push(selectedValue);
          merge.predecessors.push(end.id);
          branch.edges.push({ target: lower(expr.args[selected ? 1 : 2], arm, end.id), condition: selected });
        }
      } else {
        const skipOn = expr.name === "||";
        branch.booleanRhsTruth = !skipOn;
        const right = temporary();
        const skippedValue = temporary();
        const evaluatedValue = temporary();
        const skipped = add("operation", expr.span, { kind: "logical", expression: expr, inputs: [condition], result: skippedValue, selected: skipOn, effects: [] });
        skipped.edges.push({ target: join.id });
        const evaluated = add("operation", expr.span, { kind: "logical", expression: expr, inputs: [condition, right], result: evaluatedValue, selected: !skipOn, effects: [] });
        evaluated.edges.push({ target: join.id });
        merge.inputs.push(skippedValue, evaluatedValue);
        merge.predecessors.push(skipped.id, evaluated.id);
        branch.edges.push({ target: skipped.id, condition: skipOn }, { target: lower(expr.args[1], right, evaluated.id), condition: !skipOn });
      }
      return lower(expr.args[0], condition, branch.id);
    }
    const args = expr.kind === "map" || expr.kind === "fold" ? expr.args.slice(1) : expr.args;
    const inputs = args.map(temporary);
    const effects = operationEffects(expr, symbols, address, representationOf, resolveEffect).filter(effect => effect !== "may-abort" || expr.kind !== "call" || mayAbort(expr));
    const node = add("operation", expr.span, { kind: "evaluate", expression: expr, inputs, result, effects });
    node.edges.push({ target: next });
    if (effects.includes("may-abort")) node.edges.push({ target: cfg.abort, condition: false });
    let first = node.id;
    for (let index = args.length - 1; index >= 0; index--) first = lower(args[index], inputs[index], first, index === 0 && (expr.kind === "assign" || expr.kind === "member" && Boolean(expr.ledgerRoot)));
    return first;
  };
  for (const node of source.nodes) {
    const tail = add(node.kind, node.span);
    tail.binding = node.binding;
    tail.pattern = node.pattern;
    tails.set(node.id, tail);
  }
  cfg.entry = tails.get(source.entry)!.id;
  cfg.exit = tails.get(source.exit)!.id;
  cfg.abort = tails.get(source.abort)!.id;
  for (const node of source.nodes) {
    const tail = tails.get(node.id)!;
    if (node.expr) {
      const result = temporary();
      tail.instruction = { kind: "copy", inputs: [result], effects: [] };
      starts.set(node.id, lower(node.expr, result, tail.id));
    } else starts.set(node.id, tail.id);
  }
  for (const node of source.nodes) tails.get(node.id)!.edges = node.edges.filter(edge => edge.target !== source.abort).map(edge => ({ ...edge, target: starts.get(edge.target)! }));
  const postdominators = cfg.immediatePostdominators();
  for (const node of cfg.nodes) if (node.kind === "branch") node.join = postdominators.get(node.id);
  verifyInstructions(cfg);
  return cfg;
}

export function verifyInstructions(cfg: CFG): void {
  const reachable = cfg.reachableFrom(cfg.entry);
  const incoming = new Map([...reachable].map(node => [node, [] as number[]]));
  for (const node of cfg.nodes) for (const edge of node.edges) {
    if (!cfg.nodes[edge.target]) fail("invalid-ir", "Instruction edge targets a missing node", node.span);
    if (reachable.has(node.id)) incoming.get(edge.target)!.push(node.id);
  }
  const remaining = new Map([...incoming].map(([node, parents]) => [node, parents.length]));
  const pending = [cfg.entry];
  const parent = new Map<number, number>([[-1, -1]]);
  const depth = new Map<number, number>([[-1, 0]]);
  const definitions = new Map<string, number>();
  const common = (first: number, second: number): number => {
    while (first !== second) {
      if (depth.get(first)! >= depth.get(second)!) first = parent.get(first)!;
      else second = parent.get(second)!;
    }
    return first;
  };
  while (pending.length) {
    const node = cfg.nodes[pending.pop()!];
    const parents = incoming.get(node.id)!;
    const ancestor = parents.length ? parents.reduce(common) : -1;
    parent.set(node.id, ancestor);
    depth.set(node.id, depth.get(ancestor)! + 1);
    if (node.instruction?.result) {
      if (definitions.has(node.instruction.result)) fail("invalid-ir", "An expression temporary has more than one definition", node.span);
      definitions.set(node.instruction.result, node.id);
    }
    for (const edge of node.edges) {
      const count = remaining.get(edge.target)! - 1;
      remaining.set(edge.target, count);
      if (count === 0) pending.push(edge.target);
    }
  }
  if (parent.size !== reachable.size + 1) fail("invalid-ir", "Instruction CFG contains a cycle", cfg.nodes[cfg.entry].span);
  const children = new Map([...parent.keys()].map(node => [node, [] as number[]]));
  for (const [node, ancestor] of parent) if (node !== -1) children.get(ancestor)!.push(node);
  const intervals = new Map<number, { start: number; end: number }>();
  const traversal = [{ node: -1, done: false }];
  let clock = 0;
  while (traversal.length) {
    const current = traversal.pop()!;
    if (current.done) { intervals.get(current.node)!.end = clock++; continue; }
    intervals.set(current.node, { start: clock++, end: 0 });
    traversal.push({ ...current, done: true }, ...children.get(current.node)!.map(node => ({ node, done: false })));
  }
  for (const id of reachable) {
    const node = cfg.nodes[id];
    const instruction = node.instruction;
    if (instruction?.kind === "merge" && (instruction.inputs.length !== instruction.predecessors.length || new Set(instruction.predecessors).size !== instruction.predecessors.length || instruction.predecessors.some(predecessor => !cfg.nodes[predecessor]?.edges.some(edge => edge.target === id)) || incoming.get(id)!.some(predecessor => !instruction.predecessors.includes(predecessor)))) fail("invalid-ir", "Merge inputs must match incoming edges", node.span);
    if (instruction?.kind === "evaluate" && instruction.inputs.length !== (instruction.deferred ? 0 : instruction.expression.args.length - (["map", "fold"].includes(instruction.expression.kind) ? 1 : 0))) fail("invalid-ir", "Operator input arity does not match its expression", node.span);
    for (let index = 0; index < (instruction?.inputs.length ?? 0); index++) {
      const use = instruction!.kind === "merge" ? instruction!.predecessors[index] : id;
      if (!reachable.has(use)) continue;
      const definition = definitions.get(instruction!.inputs[index]);
      const defined = definition === undefined ? undefined : intervals.get(definition);
      const used = intervals.get(use)!;
      if (!defined || definition === id || defined.start > used.start || defined.end < used.end) fail("invalid-ir", `Temporary ${instruction!.inputs[index]} is not defined on every incoming path`, node.span);
    }
  }
}
