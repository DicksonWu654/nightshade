import type { AbstractValue } from "../dataflow/index.js";
import { ReportIdentityKeys } from "../reporting/identity-keys.js";
import { enforcedMerkleDigests, merkleDigestKey } from "../dataflow/merkle-enforcement.js";
import { enforcedEqualities } from "../dataflow/predicates.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { merklePathWitnessTargets, merkleRootCircuit } from "../semantic/merkle-targets.js";
import { spanId } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

/** Informational intent review, restricted to exact path lookups and Field hash writes.
 * Requires ordinary uncompressed histories with digest and numeric observers.
 * Provenance and regions never contribute equality edges. */
export const merkleLeafBindingReview: Detector = {
  id: "merkle-leaf-binding-review",
  description: "Checked Merkle path leaves lack binding to supplied lookup inputs or exact Field hash write candidates",
  requires: ["merkle-observations", "successful-predicates", "digest-inputs", "mint-quantity-observations", "state-writes", "completed-entries"],
  run(facts) {
    const report = new ReportIdentityKeys(facts.program, merkleLeafBindingReview.id, facts.program.rootSource.ast.span);
    if (![...facts.program.functions.keys()].some(merkleRootCircuit)) return [];
    const issue = (code: string, message: string) => facts.diagnostics.push({ code,
      message: `${message}; Merkle leaf-binding review is incomplete`, location: facts.program.rootSource.ast.span });
    if (!facts.merkleEvidence || !facts.digestEvidence || !facts.mintQuantityEvidence || facts.predicateScope !== "all") {
      issue("predicate-evidence-unavailable", "Exact Merkle, digest, numeric and all-predicate observations are required"); return [];
    }
    const witnessTargets = merklePathWitnessTargets(facts.program);
    if (!witnessTargets.complete) { issue("merkle-witness-target-budget", "Path-witness target discovery exceeded its allowance"); return []; }
    if ([...witnessTargets.targets].some(id => !facts.invocationEvidence?.includes(id))) {
      issue("predicate-evidence-unavailable", "Path-witness lookup operand snapshots are required"); return [];
    }
    let work = 0;
    const charge = (amount = 1): boolean => (work += amount) <= 1000000;
    const completed = new Set(facts.completedEntries), findings: Finding[] = [];
    for (const path of facts.paths) {
      if (!completed.has(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
      const trusted = enforcedMerkleDigests(path, 1000000 - work);
      if (!charge(trusted.work) || !trusted.complete) { issue("predicate-analysis-budget", "Root enforcement exceeded its allowance"); return []; }
      const edges = new Map<string, Set<string>>();
      if (!path.predicates) { issue("predicate-evidence-unavailable", "Successful predicates are missing"); return []; }
      for (const predicate of path.predicates) {
        const decoded = enforcedEqualities(predicate.value, predicate.truth);
        if (!charge(decoded.work) || !decoded.complete) { issue("predicate-analysis-budget", "Equality decoding exceeded its allowance"); return []; }
        for (const equality of decoded.equalities) {
          if (!charge()) { issue("predicate-analysis-budget", "Equality grouping exceeded its allowance"); return []; }
          if (!equality.equals) continue;
          const a = merkleDigestKey(equality.left), b = merkleDigestKey(equality.right);
          if (!a || !b) continue;
          for (const [from, to] of [[a, b], [b, a]]) {
            const next = edges.get(from) ?? new Set<string>(); next.add(to); edges.set(from, next);
          }
        }
      }
      for (const root of path.operations ?? []) {
        if (!charge()) { issue("predicate-analysis-budget", "Root grouping exceeded its allowance"); return []; }
        if (root.kind !== "merkle-root") continue;
        const digest = root.result.fields?.field, leaf = root.args[0]?.fields?.leaf;
        const digestKey = digest && merkleDigestKey(digest), leafKey = leaf && merkleDigestKey(leaf);
        if (!digestKey || !trusted.keys.has(digestKey) || !["Field", "Bytes<32>"].includes(leaf?.type ?? "")) continue;
        if (!leafKey) { issue("predicate-evidence-unavailable", "Checked leaf lacks an immutable key"); return []; }
        const bound = new Set([leafKey]), pending = [leafKey];
        for (let i = 0; i < pending.length; i++) for (const other of edges.get(pending[i]) ?? []) {
          if (!charge()) { issue("predicate-analysis-budget", "Equality closure exceeded its allowance"); return []; }
          if (!bound.has(other)) { bound.add(other); pending.push(other); }
        }
        const proof = immutableOperandKey(root.args[0], 1000000 - work, undefined, undefined, facts.program.meteringIdentity);
        if (!charge(proof.work) || !proof.complete) { issue("predicate-analysis-budget", "Checked path identity exceeded its allowance"); return []; }
        for (const invocation of path.operations ?? []) {
          if (!charge()) { issue("predicate-analysis-budget", "Path-witness grouping exceeded its allowance"); return []; }
          if (invocation.kind !== "circuit-invocation" || !witnessTargets.targets.has(invocation.name)) continue;
          const returned = immutableOperandKey(invocation.result, 1000000 - work, undefined, undefined, facts.program.meteringIdentity);
          if (!charge(returned.work) || !returned.complete) { issue("predicate-analysis-budget", "Returned path identity exceeded its allowance"); return []; }
          if (!proof.key || proof.key !== returned.key) continue;
          for (const [index, candidate] of invocation.args.entries()) {
            if (!charge()) { issue("predicate-analysis-budget", "Lookup input matching exceeded its allowance"); return []; }
            if (candidate.type !== leaf.type) continue;
            const key = merkleDigestKey(candidate);
            if (!key) { issue("predicate-evidence-unavailable", "Path lookup input lacks an immutable key"); return []; }
            if (bound.has(key)) continue;
            const entry = facts.program.symbols.get(path.entry)!.name;
            findings.push(finding(facts, {
              detectorId: merkleLeafBindingReview.id, severity: "info", confidence: "medium",
              title: "Checked Merkle leaf is not bound to the path lookup input",
              message: `${entry} enforces a root check on this witness-returned path without requiring its ${leaf.type} leaf to equal lookup argument ${index + 1}. Passing a value to a witness does not constrain the witness result. Review whether this argument identifies the intended member; lookup indices or independently checked inputs may be intentional.`,
              location: root.location, source: invocation.location,
              trace: [{ kind: "source", label: "path witness lookup input", location: invocation.location }, { kind: "call", label: "checked path operand", location: root.location }],
              callPath: root.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
              remediation: "When this input is the intended member, assert equality with the exact checked path leaf or construct the path's leaf from that input. Keep intentional independent lookup inputs documented.",
              metadata: { reviewRequired: true, authenticationIntent: "unknown", entry, witness: invocation.name, argumentIndex: index,
                evidence: "checked-root-without-required-lookup-input-leaf-equality", doesNotProve: "security-flaw-or-exploitability" },
            }, `${path.entry}:${spanId(root.location)}:${spanId(invocation.location)}:lookup:${index}`));
          }
        }
        if (leaf.type !== "Field") continue;
        for (const write of path.writes) {
          if (!charge()) { issue("predicate-analysis-budget", "Effect matching exceeded its allowance"); return []; }
          if (write.after.type !== "Field") continue;
          const candidates: AbstractValue[] = [], stack = [{ value: write.after, depth: 0 }];
          while (stack.length) {
            const { value, depth } = stack.pop()!;
            if (!charge() || depth > 64) { issue("predicate-analysis-budget", "Candidate traversal exceeded its allowance"); return []; }
            if (value.type === "Field" && (value.directDigest || value.summarizedMerkleHash)) candidates.push(value);
            else if (value.numericExpression) for (const operand of value.numericExpression.operands) stack.push({ value: operand, depth: depth + 1 });
          }
          for (const candidate of candidates) {
            if (!charge()) { issue("predicate-analysis-budget", "Candidate matching exceeded its allowance"); return []; }
            const key = merkleDigestKey(candidate);
            if (!key) { issue("predicate-evidence-unavailable", "Exact hash candidate lacks an immutable key"); return []; }
            if (bound.has(key)) continue;
            const entry = facts.program.symbols.get(path.entry)!.name;
            findings.push(finding(facts, {
              detectorId: merkleLeafBindingReview.id, severity: "info", confidence: "low",
              title: "Review checked Merkle leaf binding to a local hash candidate",
              message: `${entry} has a modeled successful history with a checked Merkle root and a recomputed hash influencing a Field write, without a required equality between that exact path leaf and candidate. These may be independent intentional operations; review whether this candidate is meant to be the member leaf.`,
              location: root.location, source: root.location,
              trace: [{ kind: "source", label: "checked path operand", location: root.location }, { kind: "effect", label: "hash candidate influences Field write", location: write.location }],
              callPath: root.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
              remediation: "If the candidate is intended to be the member leaf, enforce equality with the exact checked path leaf on every successful history, or construct that path using the candidate.",
              metadata: { reviewRequired: true, authenticationIntent: "unknown", entry, evidence: "checked-root-without-required-leaf-candidate-equality", doesNotProve: "security-flaw-or-exploitability" },
            }, `${path.entry}:${spanId(root.location)}:${spanId(write.location)}:${report.key(key)}`));
          }
        }
      }
    }
    return unique(findings);
  },
};
