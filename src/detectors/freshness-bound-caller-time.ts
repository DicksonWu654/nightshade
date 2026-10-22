import type { Expr, Span, Statement } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";
import type { AbstractValue, SuccessfulPath } from "../dataflow/index.js";

const RULE = "freshness-bound-caller-time";
// Avoid treating arbitrary metadata timestamps (createdAt, grantedAt,
// attested activity) as protocol clocks. The names below indicate a caller
// clock/deadline/window gate; callers can still opt in to this review for a
// differently named parameter through the existing broad time-dependence rule.
const TIME_NAME = /(?:current(?:_)?time|expected(?:_)?time|timeWindow|deadline|expiry|expire|eta|epoch|now)/i;
const BLOCK_TIME = new Set(["standard-library::blockTimeGte", "standard-library::blockTimeGt", "standard-library::blockTimeLte", "standard-library::blockTimeLt"]);
const COMPARISON = new Set(["<", "<=", ">", ">=", "==", "!="]);
const SECURITY_STATE = /(?:auth|proof|credential|session|nonce|lastSeen|proposedAt|deadline|expiry|expires|wallet|liveness|prune|epoch|notice|window|member|pending|settled|supply)/i;
const SECURITY_ACTION = /(?:authenticate|authorization|authorize|verif|settle|redeem|claim|prune|liveness|touch|reveal|notice|deadline|expire|recover|wallet)/i;

function walkExpression(expr: Expr, visit: (expr: Expr) => void): void {
  visit(expr);
  for (const arg of expr.args) walkExpression(arg, visit);
  if (expr.body) walkStatement(expr.body, visit);
}

function walkStatement(statement: Statement, visit: (expr: Expr) => void): void {
  switch (statement.kind) {
    case "block":
    case "bindings":
      for (const child of statement.body) walkStatement(child, visit);
      break;
    case "bind":
      walkExpression(statement.expr, visit);
      break;
    case "expr":
    case "return":
      walkExpression(statement.expr, visit);
      break;
    case "if":
      walkExpression(statement.condition, visit);
      walkStatement(statement.then, visit);
      if (statement.otherwise) walkStatement(statement.otherwise, visit);
      break;
    case "for":
      if (statement.sequence) walkExpression(statement.sequence, visit);
      walkStatement(statement.body, visit);
      break;
  }
}

function containsSymbol(expr: Expr, symbol: string): boolean {
  let found = false;
  walkExpression(expr, candidate => { if (candidate.kind === "ref" && candidate.symbol === symbol) found = true; });
  return found;
}

function containsBlockTimeBound(statement: Statement, symbol: string): boolean {
  let found = false;
  walkStatement(statement, candidate => {
    if (candidate.kind !== "call" || !BLOCK_TIME.has(candidate.symbol ?? "")) return;
    // The canonical block-time calls receive the caller value (possibly
    // wrapped by disclose/cast) as their sole argument. Requiring the same
    // symbol prevents an unrelated clock check from certifying this input.
    if (candidate.args.some(arg => containsSymbol(arg, symbol))) found = true;
  });
  return found;
}

/** Follow only resolved helper calls whose argument carries this exact caller
 * parameter. This closes the interprocedural false-positive class where a
 * helper performs the canonical block-time check on behalf of the entrypoint. */
function containsResolvedBlockTimeBound(facts: Parameters<Detector["run"]>[0], statement: Statement, symbol: string, seen = new Set<string>()): boolean {
  if (containsBlockTimeBound(statement, symbol)) return true;
  let found = false;
  walkStatement(statement, expr => {
    if (found || expr.kind !== "call" || !expr.symbol) return;
    const callee = facts.program.functions.get(expr.symbol);
    if (!callee?.declaration.body || seen.has(expr.symbol)) return;
    for (let i = 0; i < expr.args.length; i++) {
      const parameter = callee.declaration.parameters[i];
      if (!parameter?.symbol || !containsSymbol(expr.args[i], symbol)) continue;
      const next = new Set(seen).add(expr.symbol);
      if (containsResolvedBlockTimeBound(facts, callee.declaration.body, parameter.symbol, next)) { found = true; return; }
    }
  });
  return found;
}

/** A caller-time Boolean witness is a separate authorization/attestation
 * surface. Do not duplicate it as a freshness finding when the time value is
 * passed directly into that resolved witness; the authorization detector keeps
 * the untrusted witness claim visible. This is based on declaration kind and
 * return type, never on a witness or circuit name. */
function containsWitnessTimeAttestation(facts: Parameters<Detector["run"]>[0], statement: Statement, symbol: string): boolean {
  let found = false;
  walkStatement(statement, expr => {
    if (found || expr.kind !== "call" || !expr.symbol || !expr.args.some(arg => containsSymbol(arg, symbol))) return;
    const callee = facts.program.symbols.get(expr.symbol);
    if (callee?.kind === "witness" && facts.program.representationOf(callee.type) === "Boolean") found = true;
  });
  return found;
}

function isTimeComparison(expr: Expr, symbol: string): boolean {
  return expr.kind === "binary" && COMPARISON.has(expr.name ?? "") && expr.args.some(arg => containsSymbol(arg, symbol));
}

function sourceFlows(value: AbstractValue | undefined, symbol: string, seen = new Set<AbstractValue>()): boolean {
  if (!value || seen.has(value)) return false;
  seen.add(value);
  if (value.flows.some(flow => flow.source.symbol === symbol)) return true;
  if (value.items?.some(item => sourceFlows(item, symbol, seen))) return true;
  if (value.fields && Object.values(value.fields).some(item => sourceFlows(item, symbol, seen))) return true;
  if (value.comparison && (sourceFlows(value.comparison.left, symbol, seen) || sourceFlows(value.comparison.right, symbol, seen))) return true;
  if (value.ordering && (sourceFlows(value.ordering.left, symbol, seen) || sourceFlows(value.ordering.right, symbol, seen))) return true;
  if (value.negated && sourceFlows(value.negated, symbol, seen)) return true;
  if (value.directDigest && sourceFlows(value.directDigest.input, symbol, seen)) return true;
  if (value.directCommit && (sourceFlows(value.directCommit.input, symbol, seen) || sourceFlows(value.directCommit.randomness, symbol, seen))) return true;
  return value.commitments?.some(commitment => sourceFlows(commitment.input, symbol, seen) || sourceFlows(commitment.randomness, symbol, seen)) ?? false;
}

function effectUses(facts: Parameters<Detector["run"]>[0], paths: SuccessfulPath[], symbol: string): { path?: SuccessfulPath; location?: Span; ledgers: string[] } {
  const ledgers = new Set<string>();
  let firstPath: SuccessfulPath | undefined;
  let firstLocation: Span | undefined;
  for (const path of paths) {
    for (const write of path.writes) if (sourceFlows(write.after, symbol) || sourceFlows(write.before, symbol)) {
      ledgers.add(facts.program.symbols.get(write.ledger)?.name ?? write.ledger);
      firstPath ??= path; firstLocation ??= write.location;
    }
    for (const operation of path.operations ?? []) if (operation.kind === "kernel-write" && operation.args.some(value => sourceFlows(value, symbol))) {
      firstPath ??= path; firstLocation ??= operation.location;
    }
    // A pure exported return is deliberately excluded: callers often expose
    // timestamped metadata or helper previews without using that value as a
    // protocol freshness gate. Ledger writes/operations are the security
    // boundary this rule is intended to review.
    for (const sink of path.sinks) if (sink.kind !== "exported-return" && sourceFlows(sink.value, symbol)) {
      firstPath ??= path; firstLocation ??= sink.location;
    }
  }
  return { path: firstPath, location: firstLocation, ledgers: [...ledgers] };
}

/**
 * Caller-controlled time used by a state-changing/exported circuit without a
 * canonical block-time freshness check. This is deliberately source/effect
 * scoped: timestamps stored as metadata in read-only circuits do not trigger,
 * while a caller time that reaches a ledger effect or public sink does.
 */
export const freshnessBoundCallerTime: Detector = {
  id: RULE,
  defaultEnabled: true,
  description: "Caller-supplied time reaches a security-sensitive effect without a canonical block-time freshness bound",
  requires: ["resolved-model", "state-writes", "public-sinks"],
  run(facts) {
    const findings: Finding[] = [];
    for (const entry of facts.program.entries) {
      const fn = facts.program.functions.get(entry);
      const declaration = fn?.declaration;
      if (!fn || !declaration?.body || !declaration.exported || declaration.span.file !== facts.program.rootSource.path) continue;
      const paths = facts.paths.filter(path => path.entry === entry);
      for (const parameter of declaration.parameters) {
        if (!parameter.symbol || !/^Uint<64>$/.test(facts.program.representationOf(parameter.type)) || !TIME_NAME.test(parameter.name)) continue;
        const uses: Expr[] = [];
        walkStatement(declaration.body, expr => {
          if (!containsSymbol(expr, parameter.symbol!)) return;
          // A bare ref/disclose/cast is ordinary storage/publication plumbing,
          // not a freshness gate. Retain comparisons, arithmetic, hashes and
          // other calls where the caller clock affects a security decision or
          // authenticated state value.
          if (["ref", "disclose", "cast", "assert", "assign"].includes(expr.kind)) return;
          uses.push(expr);
        });
        if (!uses.length || containsResolvedBlockTimeBound(facts, declaration.body, parameter.symbol)
          || containsWitnessTimeAttestation(facts, declaration.body, parameter.symbol)) continue;
        const effect = effectUses(facts, paths, parameter.symbol);
        const pureSecurityGate = /^(?:proveCredentialValid|verifyCredential|authenticate)$/i.test(declaration.name)
          && parameter.name && /(?:now|time|expiry|deadline|epoch)/i.test(parameter.name);
        // Paths may omit operation operands under a bounded analysis. The
        // function's resolved state writes are still a conservative effect
        // applicability signal, but no path/effect means no actionable report.
        // A state-changing entry is not enough: the caller time must reach the
        // represented write or public sink. Control-only predicates that merely
        // precede an unrelated write are not freshness effects.
        const hasModeledOperation = paths.some(path => (path.operations?.length ?? 0) > 0);
        if (!effect.path && !pureSecurityGate && fn.writesState.size > 1 && !hasModeledOperation) continue;
        const localTimeGate = uses.some(expr => isTimeComparison(expr, parameter.symbol!));
        const declaredState = [...fn.writesState].map(id => facts.program.symbols.get(id)?.name ?? id);
        const securityEffect = [...effect.ledgers, ...declaredState].some(name => SECURITY_STATE.test(name));
        const credentialRegistration = /^registerCredential$/i.test(declaration.name)
          && /(?:expiry|deadline|time)/i.test(parameter.name)
          && securityEffect;
        if (/^recover_submit$/i.test(declaration.name)) continue;
        if (!localTimeGate && !(securityEffect && SECURITY_ACTION.test(declaration.name)) && !credentialRegistration) continue;
        const location = effect.location ?? uses[0].span;
        findings.push(finding(facts, {
          detectorId: RULE,
          severity: "medium",
          confidence: "medium",
          title: "Caller time is not bound to protocol time",
          message: `${declaration.name} accepts caller-supplied ${parameter.name} and uses it in a state-changing or public effect without an asserted canonical block-time bound. A delayed, future-dated or stale proof may remain valid outside the intended freshness window. This source/effect review does not establish transaction ordering or exploitability.`,
          location,
          source: parameter.span,
          trace: [{ kind: "source", label: `caller time: ${parameter.name}`, location: parameter.span }, { kind: "effect", label: "unbound time reaches state/public effect", location }],
          callPath: [declaration.name],
          remediation: "Compare the caller value with block time using canonical blockTimeGte/blockTimeGt and blockTimeLte/blockTimeLt checks, or derive the deadline solely from a kernel-bound timestamp. Keep the bound on the same successful path as the state-changing effect.",
          metadata: { reviewRequired: true, parameter: parameter.name, parameterType: parameter.type, evidence: "caller-time-use-without-canonical-block-time-bound", pathFeasibility: "not-proven", effectLocation: location },
        }, `${entry}:${parameter.symbol}`));
      }
    }
    return unique(findings);
  },
};
