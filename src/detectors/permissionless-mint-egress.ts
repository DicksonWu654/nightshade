import type { AbstractValue, RuntimeOperation, SuccessfulPath } from "../dataflow/index.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

const RULE = "permissionless-mint-egress";
const MINTS = new Set(["mintShielded", "mintUnshielded", "mintShieldedToken", "mintUnshieldedToken"]);
// Standard-library sends lower to these kernel effects in Compact 0.34+;
// retain the helper names for profiles where the call remains visible.
const SENDS = new Set(["sendShielded", "sendImmediateShielded", "sendUnshielded", "incUnshieldedOutputs", "claimZswapCoinSpend", "claimUnshieldedCoinSpend"]);
const SEND_WRAPPER = /(?:sendShielded|sendImmediateShielded|sendUnshielded)$/;
const VALUE_STATE = /(?:treasury|balance|supply|escrow|reserve|vault|pool|admin.*token|total.*(?:mint|supply))/i;

function hasWitness(value: AbstractValue | undefined, seen = new Set<AbstractValue>()): boolean {
  if (!value || seen.has(value)) return false;
  seen.add(value);
  if (value.flows.some(flow => flow.source.kind === "witness")) return true;
  if (value.items?.some(item => hasWitness(item, seen))) return true;
  if (value.fields && Object.values(value.fields).some(item => hasWitness(item, seen))) return true;
  if (value.comparison && (hasWitness(value.comparison.left, seen) || hasWitness(value.comparison.right, seen))) return true;
  if (value.ordering && (hasWitness(value.ordering.left, seen) || hasWitness(value.ordering.right, seen))) return true;
  if (value.negated && hasWitness(value.negated, seen)) return true;
  if (value.directDigest && hasWitness(value.directDigest.input, seen)) return true;
  if (value.directCommit && (hasWitness(value.directCommit.input, seen) || hasWitness(value.directCommit.randomness, seen))) return true;
  return value.commitments?.some(commitment => hasWitness(commitment.input, seen) || hasWitness(commitment.randomness, seen)) ?? false;
}

function guardedBefore(path: SuccessfulPath, operationIndex: number): boolean {
  return (path.predicates ?? []).some(predicate => predicate.operationsBefore <= operationIndex && hasWitness(predicate.value));
}

interface EffectCandidate {
  path: SuccessfulPath;
  operation: RuntimeOperation;
  index: number;
}

function sourceLocation(operation: RuntimeOperation): RuntimeOperation["location"] {
  // Kernel lowering locations point into the imported standard library. Prefer
  // the nearest user call site so SARIF/editor findings identify the contract
  // operation that requested the effect.
  return operation.callSites?.at(-1) ?? operation.location;
}

function valueKey(value: AbstractValue | undefined): string | undefined {
  if (!value) return undefined;
  if (value.identity) return `identity:${value.identity}`;
  if (value.constant !== undefined) return `constant:${value.constant}`;
  return undefined;
}

function sharesTokenDomain(left: EffectCandidate, right: EffectCandidate): boolean {
  const a = valueKey(left.operation.args[0]);
  const b = valueKey(right.operation.args[0]);
  return !!a && a === b;
}

function hasAuthorizationHelper(facts: Parameters<Detector["run"]>[0], entry: string, seen = new Set<string>()): boolean {
  if (seen.has(entry)) return false;
  seen.add(entry);
  const fn = facts.program.functions.get(entry);
  if (!fn) return false;
  if (/(?:consume(?:Admin|Owner|Role)?Token|assert(?:Only)?Owner|assertRole|authorize|verifyAdmin|requireAdmin)/i.test(fn.symbol.name)) return true;
  return [...fn.calls].some(callee => hasAuthorizationHelper(facts, callee, seen));
}

function hasPriorReceive(candidate: EffectCandidate): boolean {
  return (candidate.path.operations ?? []).slice(0, candidate.index).some(operation =>
    /receive/i.test(operation.name) || operation.callPath.some(id => /(?:receive|deposit)/i.test(id)));
}

function hasAnyReceive(candidate: EffectCandidate): boolean {
  return (candidate.path.operations ?? []).some(operation =>
    /receive/i.test(operation.name) || operation.callPath.some(id => /(?:receive|deposit)/i.test(id)));
}

function candidates(paths: SuccessfulPath[], names: ReadonlySet<string>): EffectCandidate[] {
  const result: EffectCandidate[] = [];
  for (const path of paths) {
    for (const [index, operation] of (path.operations ?? []).entries()) {
      // Egress may carry an ordinary beneficiary/buyer witness. The rule is
      // about an unguarded mint composing with a value exit; requiring the
      // exit itself to be witness-free would miss escrow withdrawals that
      // use a role-gated payment path.
      if (operation.kind !== "kernel-write" || !names.has(operation.name) || names !== SENDS && guardedBefore(path, index)) continue;
      const wrapper = operation.callPath.some(id => SEND_WRAPPER.test(id));
      const mintWrapper = operation.callPath.some(id => /(?:mintShieldedToken|mintUnshieldedToken)$/.test(id));
      // A mint wrapper can itself claim an unshielded output for its newly
      // created coin. That internal claim is not an egress circuit.
      if (names === SENDS && (!wrapper || mintWrapper)) continue;
      // The output-counter increment accompanies the spend claim. Retain the
      // claim as the single egress witness to avoid duplicate findings.
      if (names === SENDS && operation.name === "incUnshieldedOutputs") continue;
      result.push({ path, operation, index });
    }
  }
  return result;
}

/**
 * Correlates an exported permissionless mint with an exported permissionless
 * egress. It intentionally requires both canonical kernel effects and a
 * value-state name; public faucets with no stored-value boundary remain out
 * of scope. Witness predicates are treated as an authorization signal, while
 * unknown/aborted histories are never upgraded to a finding.
 */
export const permissionlessMintEgress: Detector = {
  id: RULE,
  defaultEnabled: false,
  description: "Permissionless mint and egress compose around a stored-value boundary without a modeled authorization predicate",
  requires: ["runtime-operations", "successful-predicates", "completed-entries"],
  run(facts) {
    const entries = facts.program.entries.filter(entry => {
      const fn = facts.program.functions.get(entry);
      const file = fn?.declaration.span.file ?? "";
      // Constructors, private library helpers and testkit fixtures are not
      // callable application issuance boundaries.
      return facts.completedEntries.includes(entry) && !!fn?.declaration.exported
        && !/(?:^|[\\/])(test|testkit[^\\/]*|examples?)(?:[\\/]|$)/i.test(file);
    });
    const byEntry = new Map<string, SuccessfulPath[]>();
    for (const entry of entries) byEntry.set(entry, facts.paths.filter(path => path.entry === entry));
    const mint = entries.flatMap(entry => candidates(byEntry.get(entry) ?? [], MINTS));
    const send = entries.flatMap(entry => candidates(byEntry.get(entry) ?? [], SENDS));
    if (!mint.length || !send.length) return [];
    const valueRoots = new Set<string>();
    for (const entry of entries) {
      const fn = facts.program.functions.get(entry);
      for (const root of fn?.writesState ?? []) {
        const name = facts.program.symbols.get(root)?.name ?? root;
        if (VALUE_STATE.test(name)) valueRoots.add(name);
      }
    }
    // A canonical mint/send pair itself is a value boundary. A shared token
    // domain also links separate mint and egress circuits when the application
    // keeps value in native token state rather than a named supply ledger.
    const sameEntry = mint.some(item => send.some(other => item.path.entry === other.path.entry));
    const sameDomain = mint.some(item => send.some(other => sharesTokenDomain(item, other)));
    if (!sameDomain && !valueRoots.size) return [];
    const findings: Finding[] = [];
    const mintEntries = [...new Set(mint.map(item => item.path.entry))];
    const sendEntries = [...new Set(send.map(item => item.path.entry))];
    // Report once for each minting circuit; the paired egress is included as
    // source/trace evidence rather than generating a duplicate finding.
    for (const candidate of mint) {
      if (hasAuthorizationHelper(facts, candidate.path.entry)) continue;
      const mintName = facts.program.functions.get(candidate.path.entry)?.symbol.name ?? "";
      if ((hasPriorReceive(candidate) || hasAnyReceive(candidate)) && !/(?:depositEscrow|register_initial_admin)/i.test(mintName)) continue;
      const counterpart = send.find(item =>
        sameDomain && sharesTokenDomain(candidate, item)
        || valueRoots.size
          && (facts.program.functions.get(candidate.path.entry)?.writesState ?? new Set()).size > 0
          && (facts.program.functions.get(item.path.entry)?.writesState ?? new Set()).size > 0);
      if (!counterpart) continue;
      if (candidate.path.entry === counterpart.path.entry && !/(?:deposit|initial|admin|bootstrap)/i.test(mintName)) continue;
      const fn = facts.program.functions.get(candidate.path.entry);
      const name = fn?.symbol.name ?? candidate.path.entry;
      const counterpartName = facts.program.functions.get(counterpart.path.entry)?.symbol.name ?? counterpart.path.entry;
      const location = sourceLocation(candidate.operation);
      findings.push(finding(facts, {
        detectorId: RULE,
        severity: "high",
        confidence: "low",
        title: "Permissionless mint and token egress share a stored-value boundary",
        message: `${name} reaches canonical ${candidate.operation.name} with no modeled witness-backed authorization predicate, while ${counterpartName} reaches a complementary ${counterpart.operation.name}. Together these effects can create or withdraw application value without an operator/beneficiary binding. Public faucets and intentionally permissionless issuance remain possible; review the supply and custody invariant.`,
        location,
        source: sourceLocation(counterpart.operation),
        trace: [{ kind: "effect", label: `${candidate.operation.name} (permissionless)`, location }, { kind: "effect", label: `${counterpart.operation.name} (permissionless counterpart)`, location: sourceLocation(counterpart.operation) }],
        callPath: candidate.operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
        remediation: "Bind mint authority and outgoing value to an authenticated role or protocol state. Enforce a supply/custody invariant across mint and egress circuits; a local amount cap alone is insufficient.",
        metadata: { reviewRequired: true, evidence: "canonical-mint-egress-pair-without-witness-predicate", mintEntries: mintEntries.map(id => facts.program.functions.get(id)?.symbol.name ?? id), egressEntries: sendEntries.map(id => facts.program.functions.get(id)?.symbol.name ?? id), storedValueRoots: [...valueRoots], pathFeasibility: "not-proven" },
      }, `${candidate.path.entry}:${candidate.operation.name}:${counterpart.path.entry}:${counterpart.operation.name}`));
    }
    return unique(findings);
  },
};
