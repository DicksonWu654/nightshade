import type { AnalysisFacts } from "../dataflow/index.js";
import type { Expr, Span, Statement } from "../model.js";
import { ledgerEffect } from "../semantic/intrinsics.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

type Rule = "caller-supplied-time-review" | "unasserted-security-result" | "witness-derived-value-review";
type Value = { key: string; parameters: string[]; ledgers: string[]; witness: boolean; predicate?: Expr; children: Value[] };
type Candidate = { rule: Rule; location: Span; key: string; parameter?: string };
type State = { locals: Map<string, Value>; versions: Map<string, number>; enforced: Set<string>; bound: Set<string>;
  clocks: Set<string>; candidates: Candidate[]; dropped: Value[]; effects: boolean; returned: boolean };
const clone = (state: State): State => ({ ...state, locals: new Map(state.locals), versions: new Map(state.versions),
  enforced: new Set(state.enforced), bound: new Set(state.bound), clocks: new Set(state.clocks),
  candidates: [...state.candidates], dropped: [...state.dropped] });
const sendRecipient = new Map([["standard-library::sendUnshielded", 2], ["standard-library::sendShielded", 1],
  ["standard-library::sendImmediateShielded", 1]]);

/** Deliberately local structural reviews, not protocol intent inference. Branch
 * states stay separate; aliases retain value snapshots across ledger writes.
 * Only direct canonical calls are recognized. No helper summaries, loops,
 * negative branch reasoning, or domain/identifier-name heuristics are used. */
function review(facts: AnalysisFacts, rule: Rule): Finding[] {
  const results: Finding[] = [];
  let work = 0;
  const charge = (depth = 0): void => {
    if (++work > 200000 || depth > 100) throw new Error("development-pattern-budget");
  };
  try {
    for (const entry of facts.program.entries) {
      const declaration = facts.program.functions.get(entry)?.declaration;
      if (!declaration?.body || declaration.span.file !== facts.program.rootSource.path) continue;
      const parameters = new Set(declaration.parameters.filter(p => p.type === "Uint<64>").map(p => p.symbol!));
      const initial: State = { locals: new Map(), versions: new Map(), enforced: new Set(), bound: new Set(), clocks: new Set(),
        candidates: [], dropped: [], effects: false, returned: false };
      const evaluate = (expr: Expr, state: State, depth = 0): Value => {
        charge(depth);
        if (expr.kind === "ref" && expr.symbol && state.locals.has(expr.symbol)) return state.locals.get(expr.symbol)!;
        const children = expr.args.map(arg => evaluate(arg, state, depth + 1));
        if (expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") return children[0];
        const ledger = expr.ledgerRoot;
        const symbol = expr.symbol ? facts.program.symbols.get(expr.symbol) : undefined;
        const witness = expr.kind === "call" && symbol?.kind === "witness";
        const key = JSON.stringify([expr.kind, expr.symbol ?? expr.name ?? expr.value ?? expr.type ?? "", expr.value,
          ledger ? state.versions.get(ledger) ?? 0 : undefined,
          witness ? expr.span.start : undefined, children.map(child => child.key)]);
        const predicate = expr.inferredType === "Boolean" && (expr.kind === "binary"
          && ["==", "!=", "<", ">", "<=", ">="].includes(expr.name ?? "")
          || expr.kind === "call" && expr.symbol?.startsWith("standard-library::")
          || expr.kind === "member" && expr.value === "call" && !!ledger);
        const opaque = expr.kind === "call" && !["intrinsic::left", "intrinsic::right"].includes(expr.symbol ?? "");
        return { key, children, parameters: opaque ? [] : expr.kind === "ref" && parameters.has(expr.symbol!) ? [expr.symbol!]
          : children.flatMap(child => child.parameters),
          ledgers: ledger ? [ledger] : opaque ? [] : children.flatMap(child => child.ledgers),
          witness: !!witness || !opaque && children.some(child => child.witness), predicate: predicate ? expr : undefined };
      };
      const enforce = (expr: Expr, state: State, depth = 0): void => {
        charge(depth);
        const value = evaluate(expr, state);
        state.enforced.add(value.key);
        if (expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") {
          enforce(expr.args[0], state, depth + 1); return;
        }
        // A local alias preserves the exact predicate, including clock identity.
        if (expr.kind === "ref" && value.predicate) {
          if (value.key === evaluate(value.predicate, state).key) enforce(value.predicate, state, depth + 1);
          return;
        }
        if (expr.kind === "binary" && expr.name === "&&") {
          for (const arg of expr.args) enforce(arg, state, depth + 1);
        }
        if (expr.kind === "call" && ["standard-library::blockTimeGte", "standard-library::blockTimeGt"].includes(expr.symbol ?? "")) {
          const parameter = value.children[0];
          if (parameter?.parameters.length === 1 && parameter.ledgers.length === 0)
            state.clocks.add(parameter.key);
        }
        if (expr.kind === "binary" && expr.name === "==") {
          const [left, right] = value.children;
          if (left.witness && right.ledgers.length && !right.witness) state.bound.add(left.key);
          if (right.witness && left.ledgers.length && !left.witness) state.bound.add(right.key);
        }
        if (expr.kind === "binary" && [">", ">=", "<", "<="].includes(expr.name ?? "")) {
          const [caller, ledger] = expr.name === "<" || expr.name === "<=" ? [...value.children].reverse() : value.children;
          if (caller.parameters.length === 1 && !caller.ledgers.length && ledger.ledgers.length && !ledger.parameters.length)
            state.candidates.push({ rule: "caller-supplied-time-review", location: expr.span, key: value.key, parameter: caller.key });
        }
      };
      const predicates = (value: Value): Value[] => value.predicate ? [value] : value.children.flatMap(predicates);
      const inspect = (expr: Expr, state: State, depth = 0): void => {
        charge(depth);
        if (expr.kind === "assert") { enforce(expr.args[0], state); return; }
        for (const child of expr.args) inspect(child, state, depth + 1);
        const value = evaluate(expr, state);
        const recipientIndex = expr.kind === "call" ? sendRecipient.get(expr.symbol ?? "") : undefined;
        const receiver = expr.args[0];
        const native = receiver?.ledgerType && facts.program.representationOf(receiver.ledgerType);
        const write = expr.kind === "assign" && !!receiver?.ledgerRoot
          || expr.kind === "member" && expr.value === "call" && !!native && ledgerEffect(native, expr.name ?? "")?.writes;
        if (write || recipientIndex !== undefined) {
          state.effects = true;
          for (const dropped of state.dropped) if (!state.enforced.has(dropped.key)) state.candidates.push({ rule: "unasserted-security-result", location: dropped.predicate!.span, key: dropped.key });
        }
        if (write) {
          for (const arg of value.children.slice(1)) for (const predicate of predicates(arg))
            if (!state.enforced.has(predicate.key)) state.candidates.push({ rule: "unasserted-security-result", location: predicate.predicate!.span, key: predicate.key });
          const root = receiver?.ledgerRoot;
          if (root) state.versions.set(root, (state.versions.get(root) ?? 0) + 1);
        }
        if (recipientIndex !== undefined) {
          let recipient = value.children[recipientIndex];
          const recipientExpr = expr.args[recipientIndex];
          const unwrap = (node: Expr): Expr => node.kind === "disclose" ? unwrap(node.args[0]) : node;
          const bare = unwrap(recipientExpr);
          if (bare.kind === "call" && ["intrinsic::left", "intrinsic::right"].includes(bare.symbol ?? "")) recipient = evaluate(bare.args[0], state);
          if (recipient.witness && !state.bound.has(recipient.key))
            state.candidates.push({ rule: "witness-derived-value-review", location: expr.span, key: recipient.key });
        }
      };
      const walk = (statement: Statement, states: State[], depth = 0): State[] => {
        charge(depth);
        if (states.length > 256) throw new Error("development-pattern-budget");
        if (statement.kind === "block" || statement.kind === "bindings") {
          for (const child of statement.body) states = walk(child, states, depth + 1);
          return states;
        }
        return states.flatMap(state => {
          if (state.returned) return [state];
          if (statement.kind === "for") throw new Error("development-pattern-loop");
          if (statement.kind === "if") {
            inspect(statement.condition, state);
            const yes = clone(state), no = clone(state);
            enforce(statement.condition, yes);
            return [...walk(statement.then, [yes], depth + 1), ...(statement.otherwise ? walk(statement.otherwise, [no], depth + 1) : [no])];
          }
          inspect(statement.expr, state);
          const value = evaluate(statement.expr, state);
          if (statement.kind === "bind" && statement.symbol) state.locals.set(statement.symbol, value);
          if (statement.kind === "expr" && value.predicate) state.dropped.push(value);
          if (statement.kind === "return") {
            // Returning a Boolean is a normal predicate API, not failed enforcement.
            if (statement.expr.inferredType !== "Boolean" && state.effects) for (const predicate of predicates(value))
              if (!state.enforced.has(predicate.key)) state.candidates.push({ rule: "unasserted-security-result", location: predicate.predicate!.span, key: predicate.key });
            state.returned = true;
          }
          return [state];
        });
      };
      for (const state of walk(declaration.body, [initial])) for (const candidate of state.candidates) {
        if (candidate.rule !== rule || rule === "caller-supplied-time-review" && (!state.effects || state.clocks.has(candidate.parameter!))) continue;
        results.push(finding(facts, { detectorId: rule, severity: "medium", confidence: "low", location: candidate.location,
          title: rule === "caller-supplied-time-review" ? "Caller Uint<64> passes a ledger bound without an enforced clock bound"
            : rule === "unasserted-security-result" ? "Predicate result reaches an effect without enforcement"
            : "Witness-derived send recipient lacks an exact ledger equality binding",
          message: rule === "caller-supplied-time-review" ? "This effect-bearing branch enforces a caller Uint<64> comparison with a ledger value, without enforcing blockTimeGte/Gt on that same value. Whether this quantity represents time requires independent review."
            : rule === "unasserted-security-result" ? "A comparison or canonical predicate is discarded before an effect, stored, or returned in an aggregate after an effect without requiring its exact outcome to be true. Recording status can be intentional; security intent is unknown."
            : "A canonical send uses a direct witness result or its projection as recipient, without an earlier exact equality assertion to a ledger-derived value on this branch. Prover-chosen recipients can be intentional; payment policy is unknown.",
          trace: [], callPath: [declaration.name],
          remediation: "Independently establish the intended invariant, then enforce the exact predicate or bind the exact effect operand before executing the effect.",
          metadata: { reviewRequired: true, evidence: "resolved-model-local-branch", pathFeasibility: "not-proven", intent: "unknown",
            scope: "direct calls and local aliases; loops and helper-mediated constraints excluded" },
        }, `${entry}:${candidate.location.start}`));
      }
    }
  } catch (error) {
    if (!(error instanceof Error) || !["development-pattern-budget", "development-pattern-loop"].includes(error.message)) throw error;
    ruleObservationIssue(facts, rule, error.message, error.message === "development-pattern-loop"
      ? "Local structural review does not model loop transfers" : "Local structural review exceeded its traversal or branch allowance");
    return [];
  }
  return unique(results);
}

function make(id: Rule, description: string): Detector {
  return { id, description, defaultEnabled: false, requires: ["resolved-model"], run: facts => review(facts, id) };
}
export const callerSuppliedTimeReview = make("caller-supplied-time-review", "Review an effect-bearing caller Uint<64>/ledger bound without a same-branch exact clock constraint; time intent unknown");
export const unassertedSecurityResult = make("unasserted-security-result", "Review predicate outcomes discarded before effects, persisted, or returned with an effect; security intent unknown");
export const witnessDerivedValueReview = make("witness-derived-value-review", "Review direct witness-derived canonical-send recipients without an exact prior ledger equality binding");
