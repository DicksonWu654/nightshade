import { successfulConstants } from "../dataflow/successful-constants.js";
import type { AbstractValue } from "../dataflow/index.js";
import { defaultAddressTargets, hasDefaultAddressEffects } from "../semantic/default-address-targets.js";
import { VALUE_TRANSFER_CIRCUITS } from "../semantic/value-transfers.js";
import { spanId, type Span } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

const ZERO32 = "00".repeat(32);
function zeroBytes(value: AbstractValue | undefined): boolean {
  return value?.constantKind === "bytes" && value.constant === ZERO32;
}
/** A definite tag selects exactly one payload; the inactive default proves nothing. */
export function defaultActiveAddress(value: AbstractValue | undefined): "left" | "right" | undefined {
  const fields = value?.fields, tag = fields?.is_left;
  if (tag?.constantKind !== "boolean" || !["true", "false"].includes(tag.constant!)) return undefined;
  const arm = tag.constant === "true" ? "left" : "right", payload = fields![arm];
  return zeroBytes(payload?.fields?.bytes ?? payload) ? arm : undefined;
}

export const defaultRecipientOrOwner: Detector = {
  id: "default-recipient-or-owner",
  defaultEnabled: false,
  description: "A successful value output or pinned Ownable update uses a known default active address",
  requires: ["all-predicates", "runtime-operations", "state-writes", "constants", "completed-entries"],
  run(facts) {
    if (!facts.program.entries.some(entry => hasDefaultAddressEffects(facts.program, entry))) return [];
    if (facts.predicateScope !== "all") {
      facts.diagnostics.push({ code: "default-address-evidence-unavailable", message: "Default-address review requires complete successful predicates; rule is incomplete", location: facts.program.rootSource.ast.span });
      return [];
    }
    let work = 0;
    const scope = defaultAddressTargets(facts.program), findings = new Map<string, Finding>();
    const emit = (entry: string, kind: "recipient" | "owner", arm: string, location: Span, callPath: string[], sites: Span[], effect: Span, operation: string) => {
      const name = facts.program.symbols.get(entry)!.name;
      const item = finding(facts, {
        detectorId: defaultRecipientOrOwner.id, severity: "medium", confidence: "high", title: `Known default active ${kind}`,
        message: `${name} uses a statically known all-zero 32-byte active ${kind} at ${operation} on a modeled successful history. Inactive Either payloads are excluded. Intentional burning, testing or authority removal can be valid; review the operation's destination policy.`,
        location, trace: [{ kind: "effect", label: `${operation}: default active ${arm} ${kind}`, location: effect }],
        callPath: callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
        remediation: "Validate the selected active recipient/owner before the operation. Use an explicit documented burn or renunciation path for intentional zero destinations; a check on the inactive arm does not validate the destination.",
        metadata: { entry: name, kind, activeArm: arm, address: ZERO32, operation, reviewRequired: true,
          evidence: "known-active-address-on-successful-history", pathFeasibility: "not-proven",
          invocationSites: [sites.map(site => ({ file: site.file, line: site.line, column: site.column }))],
          affectedEffects: [{ file: effect.file, line: effect.line, column: effect.column }] },
      }, `${entry}:${kind}:${spanId(location)}:${operation}`);
      const prior = findings.get(item.fingerprint);
      if (prior) {
        for (const key of ["invocationSites", "affectedEffects"] as const) {
          const values = [...prior.metadata[key] as unknown[], ...item.metadata[key] as unknown[]];
          prior.metadata[key] = [...new Map(values.map(value => [JSON.stringify(value), value])).values()];
        }
      } else findings.set(item.fingerprint, item);
    };
    for (const path of facts.paths) {
      if (!facts.completedEntries.includes(path.entry)) continue;
      const constants = successfulConstants(path, Math.min(100000, 1000000 - work), facts.program.meteringIdentity);
      const outputs = (path.operations ?? []).map(operation => ({ ...operation,
        args: operation.args.map(value => constants.refine(value)) }));
      const writes = path.writes.map(write => ({ ...write, after: constants.refine(write.after) }));
      work += constants.work;
      if (!constants.complete || work > 1000000) {
        facts.diagnostics.push({ code: "default-address-evidence-budget", message: "Successful destination constraints are contradictory or exhausted their bounded allowance; rule is incomplete", location: facts.program.functions.get(path.entry)!.declaration.span });
        return [];
      }
      for (const operation of outputs) {
        const shielded = operation.kind === "native-witness" && operation.name === "createZswapOutput";
        const unshielded = operation.kind === "kernel-write" && operation.name === "claimUnshieldedCoinSpend";
        if (!shielded && !unshielded) continue;
        const arm = defaultActiveAddress(operation.args[1]);
        const amount = shielded ? operation.args[0]?.fields?.value : operation.args[2];
        if (!arm || amount?.constantKind === "integer" && amount.constant === "0") continue;
        const index = operation.callPath.findIndex(id => VALUE_TRANSFER_CIRCUITS.has(id));
        const location = index >= 0 ? operation.callSites?.[index] : operation.location;
        if (!location) {
          facts.diagnostics.push({ code: "default-address-evidence-unavailable", message: "Default-recipient invocation evidence is unavailable; rule is incomplete", location: operation.location });
          continue;
        }
        emit(path.entry, "recipient", arm, location, operation.callPath,
          operation.callSites ?? [], operation.location, index >= 0 ? facts.program.symbols.get(operation.callPath[index])!.name : operation.name);
      }
      const last = new Set<string>();
      for (const write of [...writes].reverse()) {
        if (!scope.owners.has(write.ledger) || write.region.length) continue;
        if (last.has(write.ledger)) continue;
        last.add(write.ledger);
        if (write.callPath.some(id => scope.renounce.has(id))) continue;
        const arm = defaultActiveAddress(write.after);
        if (!arm) continue;
        const index = write.callPath.findIndex(id => scope.functions.has(id));
        const location = index >= 0 ? write.callSites?.[index] ?? write.location : write.location;
        emit(path.entry, "owner", arm, location, write.callPath, write.callSites ?? [], write.location, "Ownable._owner write");
      }
    }
    return [...findings.values()];
  },
};
