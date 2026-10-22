import type { Expr, Span, Statement } from "../model.js";
import type { RuntimeOperation, StateWrite, SuccessfulPath } from "../dataflow/index.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

const RULE = "mutually-exclusive-terminal-payout";
const SENDS = new Set(["sendShielded", "sendImmediateShielded", "sendUnshielded", "incUnshieldedOutputs", "claimZswapCoinSpend", "claimUnshieldedCoinSpend"]);
const SEND_WRAPPER = /(?:sendShielded|sendImmediateShielded|sendUnshielded)$/;
const MILESTONE_NAME = /(?:milestone|attest|confirm|approved|approval|verified|complete|settled|released|claimed|paid)/i;
const TERMINAL_NAME = /(?:state|status|phase|released|claimed|paid|settled|complete|closed|final)/i;
const TIME_NAME = /(?:time|timestamp|deadline|expiry|expire|timeout|window|eta)/i;
const TIME_CALL = /(?:blockTime|time)/i;
const PAYOUT_NAME = /(?:timeout|refund|release|payout|claim|withdraw|settle|finalize)/i;

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
    case "bind": walkExpression(statement.expr, visit); break;
    case "expr":
    case "return": walkExpression(statement.expr, visit); break;
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

function operationPaths(paths: SuccessfulPath[], names: ReadonlySet<string>): { path: SuccessfulPath; location: Span; operation: RuntimeOperation }[] {
  const result: { path: SuccessfulPath; location: Span; operation: RuntimeOperation }[] = [];
  for (const path of paths) for (const operation of path.operations ?? []) {
    if (operation.kind === "kernel-write" && names.has(operation.name)
      && operation.callPath.some(id => SEND_WRAPPER.test(id))) result.push({ path, location: operation.location, operation });
  }
  return result;
}

function sourceLocation(operation: RuntimeOperation): Span {
  return operation.callSites?.at(-1) ?? operation.location;
}

function nameOf(facts: Parameters<Detector["run"]>[0], id: string): string {
  return facts.program.symbols.get(id)?.name ?? id;
}
function oneTimeMilestone(facts: Parameters<Detector["run"]>[0], write: StateWrite): boolean {
  const name = nameOf(facts, write.ledger);
  if (!MILESTONE_NAME.test(name)) return false;
  return write.before.constantKind === "boolean" && write.before.constant === "false"
    && write.after.constantKind === "boolean" && write.after.constant === "true";
}
function ledgerReferenced(facts: Parameters<Detector["run"]>[0], statement: Statement, ids: Set<string>, names: Set<string>): boolean {
  let result = false;
  walkStatement(statement, expr => {
    if (expr.kind !== "ref") return;
    const symbol = expr.symbol ?? expr.ledgerRoot;
    if (symbol && (ids.has(symbol) || names.has(nameOf(facts, symbol)))) result = true;
  });
  return result;
}

function hasExclusiveStateGuard(facts: Parameters<Detector["run"]>[0], statement: Statement): boolean {
  let found = false;
  walkStatement(statement, expr => {
    if (found || expr.kind !== "binary" || !["==", "==="].includes(expr.name ?? "") || expr.args.length !== 2) return;
    const text = expr.args.map(arg => arg.kind === "ref" ? nameOf(facts, arg.symbol ?? arg.ledgerRoot ?? "") : arg.name ?? "").join(" ");
    // An explicit Locked/Pending/Active state guard plus the terminal write is
    // already a mutually exclusive payout state machine. Do not report it as
    // a missing milestone exclusion (the independent UBLP review identified
    // this concrete false-positive shape).
    if (/(?:locked|pending|active|open|funded)/i.test(text)) found = true;
  });
  return found;
}

function functionReferencesMilestone(facts: Parameters<Detector["run"]>[0], entry: string, ids: Set<string>, names: Set<string>, seen = new Set<string>()): boolean {
  if (seen.has(entry)) return false;
  seen.add(entry);
  const fn = facts.program.functions.get(entry);
  if (!fn?.declaration.body) return false;
  if (ledgerReferenced(facts, fn.declaration.body, ids, names)) return true;
  return [...fn.calls].some(callee => functionReferencesMilestone(facts, callee, ids, names, seen));
}

/**
 * Finds a timeout/refund/release payout that can run after a separate
 * one-time milestone write without checking that milestone. This is a
 * cross-entry source/effect review, intentionally limited to completed paths
 * with a canonical token send and a terminal-state write.
 */
export const mutuallyExclusiveTerminalPayout: Detector = {
  id: RULE,
  defaultEnabled: false,
  description: "Terminal payout remains reachable after a mutually exclusive one-time milestone",
  requires: ["runtime-operations", "state-writes", "completed-entries"],
  run(facts) {
    const completed = new Set(facts.completedEntries);
    const milestoneIds = new Set<string>(), milestoneNames = new Set<string>();
    for (const path of facts.paths) {
      if (!completed.has(path.entry)) continue;
      for (const write of path.writes) if (oneTimeMilestone(facts, write)) {
        milestoneIds.add(write.ledger);
        milestoneNames.add(nameOf(facts, write.ledger));
      }
    }
    if (!milestoneIds.size) return [];
    const findings: Finding[] = [];
    for (const entry of facts.program.entries) {
      if (!completed.has(entry)) continue;
      const fn = facts.program.functions.get(entry);
      const declaration = fn?.declaration;
      if (!fn || !declaration?.body || !declaration.exported || !PAYOUT_NAME.test(declaration.name)) continue;
      if (hasExclusiveStateGuard(facts, declaration.body)) continue;
      const paths = facts.paths.filter(path => path.entry === entry);
      const payouts = operationPaths(paths, SENDS);
      if (!payouts.length) continue;
      const terminalWrites = paths.flatMap(path => path.writes.filter(write => TERMINAL_NAME.test(nameOf(facts, write.ledger))));
      if (!terminalWrites.length) continue;
      let timeGate = false;
      walkStatement(declaration.body, expr => {
        if (expr.kind === "call" && TIME_CALL.test(expr.symbol ?? expr.name ?? "")) timeGate = true;
        if (expr.kind === "ref" && TIME_NAME.test(nameOf(facts, expr.symbol ?? expr.ledgerRoot ?? ""))) timeGate = true;
      });
      if (!timeGate && !TIME_NAME.test(declaration.name)) continue;
      if (functionReferencesMilestone(facts, entry, milestoneIds, milestoneNames)) continue;
      const payout = payouts[0];
      const terminal = terminalWrites[0];
      const payoutLocation = sourceLocation(payout.operation);
      findings.push(finding(facts, {
        detectorId: RULE,
        severity: "high",
        confidence: "medium",
        title: "Terminal payout lacks the milestone exclusion guard",
        message: `${declaration.name} reaches a canonical token payout after a timeout/release-style gate and writes terminal state, but does not read the one-time milestone state used by a sibling successful circuit. A timeout/refund payout can therefore remain reachable after the milestone branch succeeds. This is a cross-entry state-machine review; transaction censorship and intended policy are not established.`,
        location: payoutLocation,
        source: terminal.location,
        constraint: terminal.location,
        trace: [{ kind: "effect", label: "terminal payout", location: payoutLocation }, { kind: "effect", label: "terminal state write", location: terminal.location }],
        callPath: payout.path.entry ? payout.path.operations?.find(operation => operation.location === payout.location)?.callPath.map(id => nameOf(facts, id)) ?? [declaration.name] : [declaration.name],
        remediation: "Require the timeout/refund branch to prove the milestone has not occurred (for example, assert !milestoneConfirmed) before paying. Keep the one-time milestone and terminal payout guards mutually exclusive across exported entrypoints.",
        metadata: { reviewRequired: true, evidence: "one-time-milestone-write-plus-timeout-payout-without-milestone-read", milestoneLedgers: [...milestoneNames], payoutEntry: declaration.name, payoutLocation, terminalStateLocation: terminal.location, pathFeasibility: "not-proven" },
      }, `${entry}:${payoutLocation.file}:${payoutLocation.start}`));
    }
    return unique(findings);
  },
};
