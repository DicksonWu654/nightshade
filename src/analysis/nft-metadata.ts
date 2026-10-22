import type { AnalysisFacts, RuntimeOperation, StateWrite } from "../dataflow/index.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { mayOverlap, type Region } from "../dataflow/regions.js";
import { nonFungibleTokenIdentities } from "../semantic/openzeppelin-identities.js";
import { terminalMetadataLookup } from "../semantic/nft-metadata-targets.js";
import type { ResolvedPolicies } from "../policies.js";
import type { Diagnostic, Span } from "../model.js";

export interface NftMetadataObservation {
  consumer: string; owners: string; metadata: string; instance: string;
  location: Span; stored: Span; burn: Span; remint: Span;
}

/** Exact same-history preservation under an explicit current-incarnation policy.
 * Collection identities identify keys, never may-alias region equality. The
 * source gate establishes terminal observation order without new engine facts. */
export function nftMetadataObservations(facts: AnalysisFacts, policies?: ResolvedPolicies, allowance = 200000) {
  const { program } = facts, identity = nonFungibleTokenIdentities(program);
  const observations: NftMetadataObservation[] = [], diagnostics: Diagnostic[] = [];
  const issued = new Set<string>();
  type Relation = Pick<NftMetadataObservation, "owners" | "metadata" | "consumer">;
  const relationKey = (relation: Relation) => JSON.stringify([relation.owners, relation.metadata, relation.consumer]);
  let work = 0, complete = true;
  const charge = (depth = 0) => { if (!complete) return false; if (++work > allowance || depth > 32) complete = false; return complete; };
  const issue = (relation: Relation, code: string, message: string) => {
    const { consumer } = relation;
    const id = `${relationKey(relation)}:${code}`;
    if (issued.has(id)) return;
    issued.add(id);
    diagnostics.push({ code, message: `${message} (owners=${relation.owners}; metadata=${relation.metadata}; consumer=${consumer})`,
      location: program.functions.get(consumer)!.declaration.span,
      scope: { kind: "rule", detectorId: "stale-nft-metadata", entry: consumer } });
  };
  const key = (value: Parameters<typeof immutableOperandKey>[0]): string | undefined => {
    if (!charge()) return;
    const result = immutableOperandKey(value, Math.min(4096, Math.max(0, allowance - work)), undefined, undefined, facts.program.meteringIdentity);
    work += result.work;
    if (!result.complete || work > allowance) complete = false;
    return complete ? result.key : undefined;
  };
  for (const policy of policies?.currentNftMetadata ?? []) {
    if (!facts.completedEntries.includes(policy.consumer)) continue;
    if (!charge()) break;
    const edge = identity.instances.find(item => policy.owners.startsWith(`${item.target}::`));
    const ownerSymbol = program.symbols.get(policy.owners);
    // A declared relation is an obligation. Untrusted/namesake/custom providers
    // cannot certify it even though they supply no authenticated finding.
    if (!edge || ownerSymbol?.name !== "_owners" || !identity.authenticated(ownerSymbol.span)) {
      issue(policy, "nft-metadata-provider-unavailable", "Configured NFT metadata requires the pinned NonFungibleToken ownership ledger and authenticated dependencies"); continue;
    }
    const member = (id: string) => id.startsWith(`${edge.target}::`) && identity.functions.has(id);
    let burn: string | undefined, mint: string | undefined;
    for (const fn of program.functions.values()) {
      if (!charge()) break;
      if (member(fn.symbol.id) && fn.symbol.name === "_burn") burn = fn.symbol.id;
      if (member(fn.symbol.id) && fn.symbol.name === "_mint") mint = fn.symbol.id;
    }
    if (!complete) break;
    if (!burn || !mint) continue;
    if (program.semanticProfile !== "compact-0.34.0-zkir2") {
      issue(policy, "nft-metadata-profile-unavailable", "NFT metadata lifecycle evidence is qualified only for Compact 0.34.0/ZKIR2"); continue;
    }
    const terminal = terminalMetadataLookup(program, policy.consumer, policy.metadata, charge);
    if (!complete) break;
    if (!terminal) {
      issue(policy, "nft-metadata-consumer-unavailable", "Current NFT metadata requires a flat entry body ending in an effect-free direct metadata Map lookup"); continue;
    }
    if (!facts.collectionEvidence || facts.pathSemantics !== "equivalent-states") {
      issue(policy, "nft-metadata-observation-unavailable", "NFT metadata requires exact successful histories and collection observations"); continue;
    }
    for (const path of facts.paths) {
      if (!charge()) break;
      if (path.entry !== policy.consumer) continue;
      if (!path.operations) {
        issue(policy, "nft-metadata-observation-unavailable", "NFT metadata history is missing ordered collection operations"); continue;
      }
      let context = false;
      for (const operation of path.operations) {
        if (!charge()) break;
        if (!["collection-query", "collection-write"].includes(operation.kind)) { context = true; break; }
      }
      if (!complete) break;
      if (context) {
        issue(policy, "nft-metadata-context-unavailable", "Transaction/context effects are outside the terminal NFT metadata observation boundary"); continue;
      }
      const sinks = [];
      for (const sink of path.sinks) {
        if (!charge()) break;
        if (sink.kind === "exported-return" && sink.callPath.length === 1 && sink.callPath[0] === policy.consumer) sinks.push(sink);
      }
      if (!complete) break;
      if (sinks.length !== 1) {
        issue(policy, "nft-metadata-observation-unavailable", "NFT metadata history is missing a unique terminal exported return"); continue;
      }
      const returned = sinks[0].value, region = returned.region;
      const selector = region?.collectionSelectors?.find(item => item.index === 0);
      if (region?.root !== policy.metadata || region.path.length !== 1 || !selector) {
        issue(policy, "nft-metadata-key-unavailable", "Terminal NFT metadata lookup has no exact root-map selector"); continue;
      }
      const selectedKey = key(selector.value), payload = key(returned);
      if (!complete) break;
      if (!selectedKey || !payload || region.path.includes("key:*")) {
        issue(policy, "nft-metadata-key-unavailable", "NFT metadata key or returned scalar snapshot is unknown"); continue;
      }
      const operations: { operation: RuntimeOperation; write: StateWrite; position: number; key: string }[] = [];
      let unavailable = false;
      for (const operation of path.operations ?? []) {
        if (!charge()) break;
        const root = operation.args[0]?.region?.root;
        if (operation.kind !== "collection-write" || ![policy.owners, policy.metadata].includes(root ?? "")) continue;
        const position = operation.writesBefore, write = position === undefined ? undefined : path.writes[position];
        // A recognized whole-cache reset has no key operand. Its root write
        // participates in the later may-overlap check and invalidates old data.
        if (root === policy.metadata && operation.name === "resetToDefault" && write?.ledger === root && !write.region.length) continue;
        const operand = operation.args[1] && key(operation.args[1]);
        if (!write || write.ledger !== root || !operand || write.region.includes("key:*")) {
          unavailable = true; continue;
        }
        operations.push({ operation, write, position: position!, key: operand });
      }
      if (!complete) break;
      if (unavailable) {
        issue(policy, "nft-metadata-key-unavailable", "A relevant NFT/cache mutation lacks an exact key or ordered write observation"); continue;
      }
      let custom = false;
      for (const item of operations) {
        if (!charge()) break;
        if (item.write.ledger === policy.owners && !item.write.callPath.includes(burn) && !item.write.callPath.includes(mint)) { custom = true; break; }
      }
      if (!complete) break;
      if (custom) {
        issue(policy, "nft-metadata-lifecycle-unavailable", "Custom ownership updates are outside the authenticated burn/mint lifecycle boundary"); continue;
      }
      const slot: Region = { root: policy.metadata, path: region.path, type: returned.type ?? 'Opaque<"string">' };
      for (const old of operations) {
        if (!charge()) break;
        if (old.write.ledger !== policy.metadata || old.operation.name !== "insert" || old.key !== selectedKey) continue;
        if (key(old.write.after) !== payload) continue;
        if (!complete) break;
        // Any potentially overlapping later mutation withholds preservation.
        // Reset/unknown-key writes cover the slot; different dynamic identities
        // remain may-aliases even when they do not establish must-equality.
        let changed = false;
        for (let index = old.position + 1; index < path.writes.length; index++) {
          if (!charge()) break;
          const write = path.writes[index];
          if (mayOverlap(slot, { root: write.ledger, path: write.region, type: write.after.type ?? "unknown" })) { changed = true; break; }
        }
        if (!complete || changed) continue;
        for (const dead of operations) {
          if (!charge()) break;
          if (dead.write.ledger !== policy.owners || dead.key !== selectedKey || dead.position <= old.position || !dead.write.callPath.includes(burn)) continue;
          if (dead.write.after.fields?.is_left?.constant !== "true" || dead.write.after.fields?.left?.constant !== "0".repeat(64)) continue;
          for (const alive of operations) {
            if (!charge()) break;
            if (alive.write.ledger !== policy.owners || alive.key !== selectedKey || alive.position <= dead.position || !alive.write.callPath.includes(mint)) continue;
            const ownerSlot: Region = { root: policy.owners, path: alive.write.region, type: alive.write.after.type ?? "unknown" };
            let overwritten = false;
            for (let index = alive.position + 1; index < path.writes.length; index++) {
              if (!charge()) break;
              const write = path.writes[index];
              if (mayOverlap(ownerSlot, { root: write.ledger, path: write.region, type: write.after.type ?? "unknown" })) { overwritten = true; break; }
            }
            if (!complete || overwritten) continue;
            const site = (write: StateWrite, callee: string) => write.callSites?.[write.callPath.indexOf(callee)] ?? write.location;
            observations.push({ ...policy, instance: edge.target, location: terminal.location, stored: old.operation.location,
              burn: site(dead.write, burn), remint: site(alive.write, mint) });
          }
        }
      }
    }
  }
  if (!complete) for (const policy of policies?.currentNftMetadata ?? []) if (facts.completedEntries.includes(policy.consumer))
    issue(policy, "nft-metadata-observation-budget", "NFT metadata relation/identity observation exhausted its bounded allowance");
  // A supported history is existential evidence even when another history or
  // relation is unavailable. Diagnostics mark overall incompleteness; only
  // allowance exhaustion invalidates every observation in this pass.
  return { complete: complete && diagnostics.length === 0, work,
    observations: complete ? observations : [], diagnostics };
}
