import { createHash } from "node:crypto";
import type { AbstractValue, AnalysisFacts, PrivateSource, StateWrite, SuccessfulPath, SuccessfulPredicate } from "./index.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { immutableOperandKey } from "./immutable-key.js";
import { SECRET_BINDING_RULE, secretWitnessDeclaration, scalarSecretKeySource } from "../semantic/secret-binding.js";
import type { Span } from "../model.js";

type Charge = (work?: number, values?: number) => boolean;
export interface SecretBindingDescriptor { witness: string; primitive: string; domain: string; trustedLedger: string }
interface Binding { key: string; descriptor: SecretBindingDescriptor; source: PrivateSource; predicate: SuccessfulPredicate }
interface Reach { entry: string; path: SuccessfulPath; write: StateWrite; index: number; bindings: Map<string, Binding> }
export interface SecretBindingComparison { weaker: Reach; peer: Reach; base: Binding; additional: Binding }

/** Exact constant recipe and a single scalar raw witness hole. This key labels
 * a declaration family; it deliberately omits all invocation/value identities. */
function descriptor(facts: AnalysisFacts, hash: AbstractValue, ledger: string, charge: Charge): SecretBindingDescriptor | undefined {
  const source = hash.directHash?.source, digest = hash.directDigest;
  if (!source || !digest || digest.primitive !== "persistentHash" || hash.directHash!.primitive !== digest.primitive) return;
  charge(1, 2);
  const witness = secretWitnessDeclaration(facts.program, source);
  if (!witness) return;
  charge(0, 4 + Math.ceil((witness.length + ledger.length + digest.primitive.length) / 64));
  charge(0, 3);
  const recipe = createHash("sha256");
  let holes = 0, constants = 0;
  const visit = (value: AbstractValue, depth: number): boolean => {
    charge(1 + value.flows.length);
    if (depth > 32) throw new Error("Secret domain recipe exceeds its bounded depth");
    if (value.constant !== undefined && value.constantKind && !value.flows.length && !value.ledger.size) {
      charge(1, 3 + Math.ceil(value.constant.length / 64));
      recipe.update(JSON.stringify(["constant", value.type, value.constantKind, value.constant])); constants++; return true;
    }
    if (value.fields || value.items) {
      if (value.fields) {
        charge(0, 2);
        const names: string[] = [];
        for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { charge(1, 1); names.push(name); }
        charge(names.length * Math.max(1, Math.ceil(Math.log2(names.length + 1)))); names.sort();
        recipe.update("fields[");
        for (const name of names) { charge(1, 1 + Math.ceil(name.length / 64)); recipe.update(JSON.stringify(name)); if (!visit(value.fields[name], depth + 1)) return false; }
      } else {
        recipe.update("items[");
        for (const item of value.items!) if (!visit(item, depth + 1)) return false;
      }
      recipe.update("]"); return true;
    }
    if (value.type !== "Bytes<32>" || value.ledger.size || value.identity !== source.id || value.flows.length !== 1
      || value.flows[0].source.id !== source.id || value.flows[0].form !== "raw"
      || value.directDigest || value.directCommit || value.comparison || value.ordering || value.negated) return false;
    recipe.update("private-witness-hole"); holes++; return true;
  };
  charge(0, 2 + Math.ceil((digest.inputType?.length ?? 0) / 64));
  recipe.update(JSON.stringify(digest.inputType));
  if (!visit(digest.input, 0) || holes !== 1 || constants === 0) return;
  charge(0, 5);
  return { witness, primitive: digest.primitive, domain: recipe.digest("hex"), trustedLedger: ledger };
}

/** All matching, recursive identity work and output reservations spend the
 * original entry meters and one cumulative selected-rule value allowance. */
export function secretBindingComparisons(facts: AnalysisFacts): SecretBindingComparison[] {
  if (!facts.program.entries.length) return [];
  const evidence = facts.secretBindingEvidence;
  if (!evidence) {
    facts.diagnostics.push({ code: "secret-binding-evidence", message: "Selected secret-binding histories and budget carrier are unavailable",
      location: facts.program.rootSource.ast.span, scope: { kind: "rule", detectorId: SECRET_BINDING_RULE, entry: facts.program.entries[0] ?? "" } });
    return [];
  }
  let entry = evidence.entrySteps.keys().next().value ?? "";
  const charge: Charge = (work = 1, values = 0) => {
    const prior = evidence.entrySteps.get(entry);
    if (prior === undefined) throw new Error("Secret binding entry budget carrier is unavailable");
    evidence.entrySteps.set(entry, prior + work); facts.metrics.steps += work; facts.metrics.abstractValues += values;
    if (prior + work > evidence.maxSteps || facts.metrics.abstractValues > evidence.maxValues) throw new Error("Secret binding matching exhausted its shared work/value allowance");
    return true;
  };
  const location = (): Span => facts.program.functions.get(entry)?.declaration.span ?? facts.program.rootSource.ast.span;
  try {
    if (facts.diagnostics.length || facts.predicateScope !== "all" || !facts.digestEvidence || facts.pathSemantics !== "equivalent-states")
      throw new Error("Complete exact secret-binding histories are unavailable");
    charge(facts.completedEntries.length, 3 + facts.completedEntries.length);
    const completed = new Set(facts.completedEntries);
    for (const selected of evidence.entrySteps.keys()) if (!completed.has(selected)) throw new Error("A selected sibling writer did not complete");
    const reaches: Reach[] = [];
    const pathReaches = new Map<SuccessfulPath, Reach[]>();
    for (const path of facts.paths) {
      entry = path.entry; charge(1, 5);
      if (!path.predicates) throw new Error("Secret-binding predicate history is unavailable");
      const rawPublic = new Set<string>(), scalarSources = new Set<string>(), edges = new Map<string, Set<string>>();
      const key = (value: AbstractValue) => {
        const result = immutableOperandKey(value, 4096, undefined, charge);
        if (!result.complete) throw new Error("Secret-binding immutable identity is unavailable");
        return result.key;
      };
      const seed = (value: AbstractValue, depth = 0): void => {
        charge(1 + value.flows.length);
        if (depth > 32) throw new Error("Secret publication traversal exceeds its bounded depth");
        if (value.fields) { for (const name in value.fields) if (Object.hasOwn(value.fields, name)) seed(value.fields[name], depth + 1); }
        else if (value.items) { for (const item of value.items) seed(item, depth + 1); }
        else if (!value.flows.length && (value.constant !== undefined || value.preexistingLedger?.size) || value.flows.some(flow => flow.form === "raw" && flow.source.id === value.identity)) {
          const id = key(value); if (id) { charge(0, 1); rawPublic.add(id); }
        }
      };
      // Sinks expose only raw operands, not the preimages of disclosed hashes.
      for (const sink of path.sinks) {
        seed(sink.value);
        for (const flow of sink.value.flows) {
          charge(); if (flow.form === "raw") {
            charge(0, 3 + Math.ceil(flow.source.id.length / 64));
            const id = `id:${flow.source.id}`; rawPublic.add(id);
            if (scalarSecretKeySource(facts.program, flow.source, charge)) scalarSources.add(id);
          }
        }
      }
      for (const predicate of path.predicates) {
        const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
          if (!equality.equals) return [];
          const a = key(equality.left), b = key(equality.right);
          if (!a || !b) return [];
          charge(0, 4 + Math.ceil((a.length + b.length) / 64));
          return [{ key: JSON.stringify([a, b]), value: [a, b, equality.left, equality.right] as const }];
        }, charge);
        if (!projected) throw new Error("Secret-binding Boolean equality projection is unavailable");
        for (const [a, b, left, right] of projected.required.values()) {
          charge(1, 4);
          for (const [id, other, value] of [[a, b, left], [b, a, right]] as const) {
            const neighbors = edges.get(id) ?? new Set<string>(); neighbors.add(other); edges.set(id, neighbors);
            if (!value.flows.length && (value.constant !== undefined || value.preexistingLedger?.size)) rawPublic.add(id);
            charge(value.flows.length);
            const scalar = !value.fields && !value.items && value.flows.find(flow => flow.form === "raw" && flow.source.id === value.identity);
            if (scalar && scalarSecretKeySource(facts.program, scalar.source, charge, value.type)) {
              charge(0, 1); scalarSources.add(id);
            }
          }
        }
      }
      charge(0, rawPublic.size);
      const pending = [...rawPublic];
      for (let index = 0; index < pending.length; index++) for (const other of edges.get(pending[index]) ?? []) {
        charge(); if (!rawPublic.has(other)) { charge(0, 2); rawPublic.add(other); pending.push(other); }
      }
      // A Map path encodes the exact immutable operand selected by the shared
      // ordinary transfer. Required equalities can prove two different operand
      // encodings equal within this atomic history, including late assertions.
      // No current storage alias or cross-entry descriptor supplies an edge.
      const operand = (path: string): string | undefined => {
        charge(1, 1 + Math.ceil(path.length / 64));
        if (!path.startsWith("key:") || path === "key:*") return;
        return path.startsWith("key:identity:") ? path.slice("key:identity:".length) : `constant:${path.slice("key:".length)}`;
      };
      const congruent = (first: string, second: string): boolean => {
        const a = operand(first), b = operand(second);
        if (!a || !b) return false;
        if (a === b) return true;
        charge(0, 4);
        const visited = new Set<string>([a]), pending = [a];
        for (let index = 0; index < pending.length; index++) for (const other of edges.get(pending[index]) ?? []) {
          charge(); if (other === b) return true;
          if (!visited.has(other)) { charge(0, 2); visited.add(other); pending.push(other); }
        }
        // The required equality graph proves scalar operand equality, not
        // congruence of aggregate recipes, arithmetic or native applications.
        // If a different represented derived key could hide such congruence,
        // absence of a graph edge cannot become a missing-binding conclusion.
        if ((!scalarSources.has(a) && !a.startsWith("constant:")) || (!scalarSources.has(b) && !b.startsWith("constant:")))
          throw new Error("Compound or derived collection-key congruence is unavailable for different operand encodings");
        return false;
      };
      const local: Reach[] = []; pathReaches.set(path, local);
      for (let index = 0; index < path.writes.length; index++) {
        const write = path.writes[index]; charge(1 + write.region.length);
        charge(0, Math.ceil(write.region.reduce((size, part) => size + part.length, 0) / 64));
        if (write.region.length !== 1 || !write.region[0].startsWith("key:") || write.region[0] === "key:*"
          || !/^(Field|Uint<\d+>)$/.test(facts.program.representationOf(write.before.type ?? "unknown"))) continue;
        charge(0, 5);
        const bindings = new Map<string, Binding>();
        for (const predicate of path.predicates) {
          const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
            charge(); if (!equality.equals) return [];
            for (const [hash, trusted] of [[equality.left, equality.right], [equality.right, equality.left]]) {
              charge(1 + (trusted.region?.path.length ?? 0));
              const region = trusted.region;
              if (!region || region.path.length !== 1 || region.revision !== 0 || !hash.directHash
                || trusted.preexistingLedger?.size !== 1 || !trusted.preexistingLedger.has(region.root)) continue;
              if (!congruent(region.path[0], write.region[0])) continue;
              // The exact pre-existing trusted record must remain unchanged at
              // the effect and when the assertion reads/enforces it. Later
              // numeric balance credits do not invalidate this occurrence.
              let changed = false;
              for (let prior = 0; prior < Math.max(index, predicate.writesBefore); prior++) {
                charge(); if (path.writes[prior].ledger === region.root) changed = true;
              }
              if (changed || !hash.directHash) continue;
              if (!hash.directDigest) throw new Error("Exact secret hash domain input is unavailable");
              const source = hash.directHash.source;
              charge(0, 2 + Math.ceil(source.id.length / 64));
              if (rawPublic.has(`id:${source.id}`)) continue;
              const binding = descriptor(facts, hash, region.root, charge);
              if (!binding) continue;
              charge(0, 8 + Math.ceil((binding.witness.length + binding.trustedLedger.length) / 64));
              const id = JSON.stringify(binding);
              return [{ key: id, value: { key: id, descriptor: binding, source, predicate } }];
            }
            return [];
          }, charge);
          if (!projected) throw new Error("Secret-binding Boolean guard projection is unavailable");
          for (const [id, binding] of projected.required) { charge(1, 1); bindings.set(id, binding); }
        }
        if (bindings.size) { charge(0, 5); const reach = { entry, path, write, index, bindings }; local.push(reach); reaches.push(reach); }
      }
    }
    const comparisons: SecretBindingComparison[] = [], emitted = new Set<string>();
    for (const weaker of reaches) {
      entry = weaker.entry; charge();
      for (const base of weaker.bindings.values()) for (const peer of reaches) {
        charge();
        if (peer.entry === weaker.entry || peer.write.ledger !== weaker.write.ledger || !peer.bindings.has(base.key)) continue;
        for (const additional of peer.bindings.values()) {
          charge();
          if (weaker.bindings.has(additional.key) || additional.descriptor.witness === base.descriptor.witness
            || additional.descriptor.domain === base.descriptor.domain || additional.descriptor.trustedLedger === base.descriptor.trustedLedger) continue;
          let required = true;
          for (const path of facts.paths) {
            charge(); if (path.entry !== peer.entry) continue;
            // No union of exclusive effects or keys: every successful sibling
            // history must contain one exact co-bound occurrence of this pair.
            let present = false;
            for (const candidate of pathReaches.get(path) ?? []) {
              charge(); if (candidate.write.ledger === peer.write.ledger && candidate.bindings.has(base.key) && candidate.bindings.has(additional.key)) present = true;
            }
            if (!present) required = false;
          }
          if (!required) continue;
          charge(0, 10 + Math.ceil((weaker.entry.length + weaker.write.location.file.length + additional.key.length) / 64));
          charge(weaker.write.callSites?.length ?? 0, 4 + (weaker.write.callSites?.length ?? 0) * 4);
          const sites = weaker.write.callSites?.map(site => [site.file, site.start, site.end]);
          for (const site of weaker.write.callSites ?? []) charge(0, 2 + Math.ceil(site.file.length / 64));
          const id = JSON.stringify([weaker.entry, weaker.write.location.file, weaker.write.location.start, weaker.index, sites, additional.key]);
          if (emitted.has(id)) continue;
          // Reserve finding, metadata, bounded trace and call-stack labels before
          // the detector formats them. Spans/descriptors remain borrowed.
          let textUnits = weaker.entry.length + peer.entry.length + weaker.write.ledger.length + base.key.length + additional.key.length;
          for (const symbol of weaker.write.callPath) { charge(); textUnits += symbol.length; }
          for (const site of weaker.write.callSites ?? []) { charge(); textUnits += site.file.length; }
          // finding() normalizes the discriminator through the source inventory.
          // Account for its sorted inventory, replacements and fingerprint text.
          const files = facts.program.files.size;
          charge(files * Math.max(1, Math.ceil(Math.log2(files + 1))), files);
          for (const file of facts.program.files.keys()) { charge(); textUnits += file.length + weaker.write.location.file.length + additional.key.length; }
          charge(8 + Math.ceil(textUnits / 64), 80 + Math.ceil(textUnits / 64) + (weaker.write.callPath.length + (weaker.write.callSites?.length ?? 0)) * 4);
          emitted.add(id); comparisons.push({ weaker, peer, base, additional });
        }
      }
    }
    return comparisons;
  } catch (error) {
    facts.diagnostics.push({ code: /allowance|depth/.test(String(error)) ? "secret-binding-budget" : "secret-binding-evidence",
      message: error instanceof Error ? error.message : String(error), location: location(),
      scope: { kind: "rule", detectorId: SECRET_BINDING_RULE, entry } });
    return [];
  }
}
