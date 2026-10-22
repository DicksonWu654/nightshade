import type { AbstractValue, AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { CONTRACT_RECIPIENT_RULE, CONTRACT_RECIPIENT_SENDS, contractRecipientType, recipientTagParameter, type RecipientCharge } from "../semantic/contract-recipient.js";
import { immutableOperandKey } from "./immutable-key.js";
import { enforcedEqualities } from "./predicates.js";
import type { Diagnostic } from "../model.js";

export interface ContractRecipientObservation { entry: string; operation: RuntimeOperation; recipient: AbstractValue; specializedParameter?: string }

/** The canonical send's modeled self test separates auto-receive histories.
 * Exact immutable bytes operands, never a wildcard path or taint union. */
function selfRelation(path: SuccessfulPath, address: AbstractValue, charge: RecipientCharge, remaining: () => number): "self" | "non-self" | undefined {
  if (address.kernelSelf || address.fields?.bytes?.kernelSelf) return "self";
  const bytes = address.fields?.bytes;
  if (!bytes) throw new Error("Native recipient address bytes are unavailable");
  const key = (part: AbstractValue) => {
    const result = immutableOperandKey(part, Math.min(4096, remaining()), undefined, charge);
    if (!result.complete || !result.key) throw new Error("Recipient immutable operand identity is unavailable");
    return result.key;
  };
  const target = key(bytes);
  let relation: "self" | "non-self" | undefined;
  for (const predicate of path.predicates!) {
    charge();
    const decoded = enforcedEqualities(predicate.value, predicate.truth, charge);
    if (!decoded.complete) throw new Error("Recipient self predicate structure is unavailable");
    for (const pair of decoded.equalities) {
      charge();
      const operand = pair.left.kernelSelf ? pair.right : pair.right.kernelSelf ? pair.left : undefined;
      if (!operand || key(operand) !== target) continue;
      const next = pair.equals ? "self" : "non-self";
      if (relation && relation !== next) throw new Error("Recipient self predicate history is inconsistent");
      relation = next;
    }
  }
  return relation;
}

export function contractRecipientObservations(facts: AnalysisFacts, deferSuppliedTags = false) {
  const observations: ContractRecipientObservation[] = [], diagnostics: Diagnostic[] = [];
  const pendingParameters: string[] = [];
  const evidence = facts.contractRecipientEvidence;
  if (!evidence) {
    diagnostics.push({ code: "contract-recipient-evidence-unavailable", message: "Exact recipient histories are unavailable", location: facts.program.rootSource.ast.span });
    return { observations, diagnostics, pendingParameters };
  }
  let work = 0, retained = 0;
  const charge: RecipientCharge = (amount = 1, values = 0) => {
    work += amount; retained += values;
    if (facts.metrics.steps + work > evidence.maxSteps || facts.metrics.abstractValues + retained > evidence.maxValues)
      throw new Error("Recipient proof exhausted its shared work/value allowance");
    return true;
  };
  const remaining = () => Math.max(0, evidence.maxSteps - facts.metrics.steps - work);
  try {
    charge(facts.completedEntries.length);
    if (facts.program.compilerVersion !== "0.34.0" || facts.program.zkirVersion !== 2)
      throw new Error("Recipient self/auto-receive review requires the supported Compact 0.34.0/ZKIR2 library");
    if (!facts.completedEntries.includes(evidence.entry) || facts.diagnostics.length || facts.predicateScope !== "all"
      || facts.pathSemantics !== "equivalent-states" || !facts.invocationEvidence
      || ![...CONTRACT_RECIPIENT_SENDS].every(id => facts.invocationEvidence!.includes(id)) || evidence.histories !== facts.paths.length)
      throw new Error("Complete exact recipient histories are unavailable");
    for (const path of facts.paths) {
      charge();
      if (path.entry !== evidence.entry || !path.predicates || !path.contractRecipientHistory
        || path.contractRecipientHistory.operations !== (path.operations?.length ?? 0)
        || path.contractRecipientHistory.predicates !== path.predicates.length)
        throw new Error("Recipient original history coverage is unavailable");
      for (const operation of path.operations ?? []) {
        charge();
        if (operation.kind !== "circuit-invocation" || !CONTRACT_RECIPIENT_SENDS.has(operation.name)) continue;
        // sendImmediateShielded's internal sendShielded is the same obligation.
        charge(operation.callPath.length);
        let nested = false;
        for (let index = 0; index + 1 < operation.callPath.length; index++)
          if (CONTRACT_RECIPIENT_SENDS.has(operation.callPath[index])) nested = true;
        if (nested) continue;
        if (!operation.callSites || operation.callSites.length !== operation.callPath.length)
          throw new Error("Recipient canonical invocation identity is unavailable");
        const recipient = operation.args[1];
        if (!recipient || !contractRecipientType(facts.program, recipient.type ?? "")) throw new Error("Canonical recipient operand layout is unavailable");
        const tag = recipient.fields?.is_left;
        if (!tag) throw new Error("Canonical recipient tag snapshot is unavailable");
        if (tag.constantKind === "boolean" && tag.constant === "true") continue;
        if (tag.constantKind !== "boolean" || tag.constant !== "false") {
          charge(facts.program.functions.get(path.entry)!.declaration.parameters.length);
          const parameter = recipientTagParameter(facts.program, path.entry, tag);
          if (parameter) {
            if (!deferSuppliedTags) throw new Error("Supplied recipient tag requires a separately completed right-arm specialization");
            charge(pendingParameters.length);
            if (!pendingParameters.includes(parameter)) { charge(0, 1); pendingParameters.push(parameter); }
            continue;
          }
          throw new Error("Recipient tag is opaque or outside the exact supplied-parameter specialization");
        }
        const address = recipient.fields!.right;
        if (!address) throw new Error("Active native ContractAddress operand is unavailable");
        const relation = selfRelation(path, address, charge, remaining);
        if (relation === "self") continue;
        if (relation !== "non-self") throw new Error("Exact non-self recipient relation is unavailable");
        let emission = 120 + operation.callPath.length * 4 + operation.callSites.length * 4;
        charge(2); emission += Math.ceil(path.entry.length / 64) * 4 + Math.ceil(operation.location.file.length / 64) * 4;
        for (const text of operation.callPath) { charge(); emission += Math.ceil(text.length / 64) * 4; }
        charge(emission, emission);
        observations.push({ entry: path.entry, operation, recipient, specializedParameter: evidence.parameter });
      }
    }
  } catch (error) {
    observations.length = 0;
    pendingParameters.length = 0;
    diagnostics.push({ code: "contract-recipient-evidence-unavailable", message: error instanceof Error ? error.message : String(error),
      location: facts.program.functions.get(evidence.entry)!.declaration.span,
      scope: { kind: "rule", detectorId: CONTRACT_RECIPIENT_RULE, entry: evidence.entry } });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += retained; }
  evidence.pendingTagParameters = pendingParameters;
  return { observations, diagnostics, pendingParameters };
}
