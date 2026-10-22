import type { Expr, Statement } from "../model.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

const RULE = "caller-supplied-deadline";
type Origin = { parameters: Set<string>; ledgers: Set<string>; delayed: boolean };
const empty = (): Origin => ({ parameters: new Set(), ledgers: new Set(), delayed: false });
const merge = (parts: Origin[]): Origin => ({
  parameters: new Set(parts.flatMap(part => [...part.parameters])),
  ledgers: new Set(parts.flatMap(part => [...part.ledgers])),
  delayed: parts.some(part => part.delayed),
});

/** Review a caller-provided time used to pass a ledger-derived deadline. This
 * intentionally recognizes only local aliases, casts and arithmetic in the
 * exported circuit; an unknown helper does not invent deadline provenance. */
export const callerSuppliedDeadline: Detector = {
  id: RULE, defaultEnabled: true,
  description: "Caller-supplied time satisfies a ledger-derived delay without a chain-time upper bound",
  requires: ["resolved-model"],
  run(facts) {
    const findings: Finding[] = [];
    let work = 0, exhausted = false;
    const charge = (depth: number): boolean => {
      if (++work > 200000 || depth > 128) exhausted = true;
      return !exhausted;
    };
    for (const fn of facts.program.functions.values()) {
      const declaration = fn.declaration;
      if (!declaration.exported || !declaration.body || declaration.span.file !== facts.program.rootSource.path) continue;
      const timeParameters = new Map(declaration.parameters
        .filter(parameter => parameter.symbol && /^Uint<64>$/.test(parameter.type) && /(?:time|timestamp|^now$)/i.test(parameter.name))
        .map(parameter => [parameter.symbol!, parameter]));
      if (!timeParameters.size) continue;
      const candidates: { expression: Expr; parameter: string; ledgers: string[] }[] = [];
      const clockBound = new Set<string>();
      const inspect = (expr: Expr, locals: Map<string, Origin>, depth: number, asserted = false): Origin => {
        if (!charge(depth)) return empty();
        if (expr.kind === "ref") {
          if (expr.symbol && timeParameters.has(expr.symbol)) return { parameters: new Set([expr.symbol]), ledgers: new Set(), delayed: false };
          if (expr.ledgerRoot) return { parameters: new Set(), ledgers: new Set([expr.ledgerRoot]), delayed: false };
          return locals.get(expr.symbol ?? "") ?? empty();
        }
        // Only the direct assertion condition (through transparent wrappers)
        // is enforced. A predicate nested in a helper or disjunction is not.
        const childAsserted = expr.kind === "assert" ? true
          : expr.kind === "disclose" || expr.kind === "cast" ? asserted : false;
        const childOrigins = expr.args.map(arg => inspect(arg, locals, depth + 1, childAsserted));
        const joined = merge(childOrigins);
        if (expr.kind === "call") {
          if (asserted && ["standard-library::blockTimeGte", "standard-library::blockTimeGt"].includes(expr.symbol ?? ""))
            for (const parameter of joined.parameters) clockBound.add(parameter);
          return empty();
        }
        if (expr.kind === "binary" && expr.args.length === 2) {
          const [left, right] = childOrigins;
          const ordered = [">=", ">"].includes(expr.name ?? "") ? [left, right]
            : ["<=", "<"].includes(expr.name ?? "") ? [right, left] : undefined;
          if (asserted && ordered?.[1].delayed && ordered[1].ledgers.size)
            for (const parameter of ordered[0].parameters) candidates.push({ expression: expr, parameter, ledgers: [...ordered[1].ledgers] });
          return { ...joined, delayed: joined.delayed || (expr.name === "+" && joined.ledgers.size > 0) };
        }
        if (expr.kind === "cast" || expr.kind === "disclose" || expr.kind === "assert" || expr.kind === "unary") return joined;
        return empty();
      };
      const walk = (statement: Statement, locals: Map<string, Origin>, depth: number): void => {
        if (!charge(depth)) return;
        if (statement.kind === "block" || statement.kind === "bindings") {
          for (const child of statement.body) walk(child, locals, depth + 1);
        } else if (statement.kind === "bind") {
          const origin = inspect(statement.expr, locals, depth + 1);
          if (statement.symbol) locals.set(statement.symbol, origin);
        } else if (statement.kind === "if") {
          inspect(statement.condition, locals, depth + 1);
          walk(statement.then, new Map(locals), depth + 1);
          if (statement.otherwise) walk(statement.otherwise, new Map(locals), depth + 1);
        } else if (statement.kind === "for") {
          if (statement.sequence) inspect(statement.sequence, locals, depth + 1);
          walk(statement.body, new Map(locals), depth + 1);
        } else inspect(statement.expr, locals, depth + 1);
      };
      walk(declaration.body, new Map(), 0);
      for (const candidate of candidates) {
        if (clockBound.has(candidate.parameter)) continue;
        const parameter = timeParameters.get(candidate.parameter)!;
        findings.push(finding(facts, {
          detectorId: RULE, severity: "medium", confidence: "medium",
          title: "Caller time can satisfy a ledger deadline",
          message: `${declaration.name} compares caller-supplied ${parameter.name} with a ledger-derived delayed value, but this circuit does not assert that the supplied time is at or before chain time. A caller may be able to pass the delay early.`,
          location: candidate.expression.span, trace: [], callPath: [declaration.name],
          remediation: "Bind the supplied time to protocol block time in this circuit, or compare the ledger deadline directly with block time. Check both the circuit that records the start time and the circuit that executes after the delay.",
          metadata: { reviewRequired: true, sourcePattern: "unbound-caller-time-versus-ledger-delay", parameter: parameter.name,
            ledgers: candidate.ledgers.map(id => facts.program.symbols.get(id)?.name ?? id), scope: "exported-root-circuit",
            temporalParameterHeuristic: "Uint<64> with time/now in the parameter name", pathFeasibility: "not-proven" },
        }));
      }
    }
    if (exhausted) {
      ruleObservationIssue(facts, RULE, "caller-deadline-budget", "Caller-supplied deadline source traversal allowance exhausted");
      return [];
    }
    return unique(findings);
  },
};
