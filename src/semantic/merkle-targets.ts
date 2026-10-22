import { createHash } from "node:crypto";
import type { Program } from "./index.js";
import { parseType, printType } from "./types.js";
import { legacyStandardLibrary, standardLibrary } from "./stdlib.js";

// Pin the helper bodies too: paths/callsets alone would admit an added assert.
const qualifiedMerkleSources = new Set(([
  [standardLibrary, "166487c61232e4058f0a5cb1a2a154d5b926a574ba5bc24f5def905c2a938e52"],
  [legacyStandardLibrary, "86196ccf76fab382c39005dba79e863c77f502d858d47a5547f263efab476884"],
] as const).flatMap(([source, expected]) =>
  createHash("sha256").update(source.text).digest("hex") === expected ? [source.path] : []));

/** Selects native insertion observations; it is not a callable symbol. */
export const MERKLE_INSERT_OBSERVER = "ledger-observation::merkle-insert";
export const MERKLE_INSERT_RULE = "merkle-insert-without-dedupe";

/** Conservative admission for bounded insertion review. Writes to a native
 * tree (including nested receivers) admit analysis; they do not prove insert. */
export function merkleInsertScope(program: Program, entries: readonly string[] = program.entries, allowance = 20000) {
  let work = 0;
  const pending = entries.filter(entry => program.symbols.get(entry)?.kind !== "constructor"), seen = new Set<string>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const ledger of fn?.writesState ?? []) {
      if (++work > allowance) return { complete: false, applicable: true };
      const type = program.symbols.get(ledger)?.type;
      if (!type) return { complete: false, applicable: true };
      const scope = containsMerkleTree(program, type, Math.min(4096, allowance - work));
      // Charge the bounded traversal conservatively; applicability cannot
      // hide unfinished discovery as a clean absence.
      work += scope.work;
      if (!scope.complete) return { complete: false, applicable: true };
      if (scope.present) return { complete: true, applicable: true };
    }
    for (const next of fn?.calls ?? []) { if (++work > allowance) return { complete: false, applicable: true }; pending.push(next); }
  }
  return { complete: true, applicable: false };
}

/** These identities belong to parsed, pinned stdlib declarations, including
 * their semantic generic specializations. Namesake user functions do not match. */
export function merkleRootCircuit(id: string): boolean {
  return ["merkleTreePathRoot", "merkleTreePathRootNoLeafHash"].some(name => id.startsWith(`standard-library::${name}<`));
}

/** Only byte-identical pinned 0.30/0.31/0.34 ZKIR2 pure root helper closures
 * have the reviewed transfer. Each profile still checks its canonical calls.
 * Field and Bytes<32> are the represented, native-legal leaf types used by this
 * review. Other profiles and shapes retain ordinary interpretation. */
export function merklePureRootSummaryTarget(program: Program, id: string): { depth: number; leaf: "Field" | "Bytes<32>"; noLeafHash: boolean } | undefined {
  if (!["0.30.0", "0.31.1", "0.34.0"].includes(program.compilerVersion) || program.zkirVersion !== 2) return;
  const source = program.compilerVersion === "0.34.0" ? standardLibrary : legacyStandardLibrary;
  if (!qualifiedMerkleSources.has(source.path)) return;
  const fn = program.functions.get(id), helper = program.functions.get("standard-library::merkleTreePathEntryRoot");
  if (!fn || !helper || fn.declaration.span.file !== source.path || helper.declaration.span.file !== source.path
    || fn.readsState.size || fn.writesState.size || fn.emitsEvent || helper.readsState.size || helper.writesState.size || helper.emitsEvent
    || fn.declaration.parameters.length !== 1 || helper.declaration.parameters.length !== 2
    || fn.symbol.type !== "standard-type::MerkleTreeDigest" || helper.symbol.type !== "Field") return;
  const term = parseType(program.representationOf(fn.declaration.parameters[0].type));
  const depth = Number(term.args[0]?.name);
  // The 0.30/0.31 standard library permits 100-level proofs. Keep a finite
  // structural cap, but admit those canonical paths to the linear summary;
  // interpreting each direction as a branch would otherwise manufacture
  // 2^depth histories and exhaust the shared analysis budget.
  if (term.name !== "MerkleTreePath" || term.args.length !== 2 || !Number.isSafeInteger(depth) || depth < 0 || depth > 256) return;
  const leaf = printType(term.args[1]);
  if (leaf !== "Field" && leaf !== "Bytes<32>") return;
  const noLeafHash = id === `standard-library::merkleTreePathRootNoLeafHash<${depth}>`;
  if ((!noLeafHash && id !== `standard-library::merkleTreePathRoot<${depth},${leaf}>`)
    || (noLeafHash && leaf !== "Bytes<32>")) return;
  if (fn.declaration.parameters[0].type !== `standard-type::MerkleTreePath<${depth},${leaf}>`
    || helper.declaration.parameters[0].type !== "Field"
    || helper.declaration.parameters[1].type !== "standard-type::MerkleTreePathEntry") return;
  const sameCalls = (actual: ReadonlySet<string>, expected: readonly string[]) => actual.size === expected.length && expected.every(call => actual.has(call));
  if (!sameCalls(helper.calls, ["intrinsic::transientHash"])
    || !sameCalls(fn.calls, noLeafHash
      ? ["intrinsic::degradeToTransient", "standard-library::merkleTreePathEntryRoot"]
      : ["intrinsic::persistentHash", "intrinsic::degradeToTransient", "standard-library::merkleTreePathEntryRoot"])) return;
  return { depth, leaf, noLeafHash };
}

/** Direct canonical path-returning witnesses, including imported aliases.
 * Selected invocation snapshots expose lookup inputs; they supply no binding. */
export function merklePathWitnessTargets(program: Program, allowance = 20000): { complete: boolean; targets: Set<string>; work: number } {
  const targets = new Set<string>();
  let work = 0;
  for (const symbol of program.symbols.values()) {
    if (++work > allowance) return { complete: false, targets, work };
    if (symbol.kind === "witness" && parseType(program.representationOf(symbol.type)).name === "MerkleTreePath") targets.add(symbol.id);
  }
  return { complete: true, targets, work };
}

/** Policy selector scope: all native tree receivers under this ledger root.
 * Bounded canonical traversal; namesake user types never become native trees. */
export function containsMerkleTree(program: Program, type: string, allowance = 4096): { complete: boolean; present: boolean; work: number } {
  const seen = new Set<string>();
  let work = 0, complete = true;
  const visit = (type: string, depth = 0): boolean => {
    if (++work > allowance || depth > 16) { complete = false; return false; }
    if (seen.has(type)) return false;
    seen.add(type);
    const term = parseType(program.representationOf(type));
    if (["MerkleTree", "HistoricMerkleTree"].includes(term.name)) return true;
    const fields = program.fieldsOf(type);
    return fields ? Object.values(fields).some(child => visit(child, depth + 1))
      : ["Map", "List", "Vector", "$tuple"].includes(term.name) && term.args.some(child => visit(printType(child), depth + 1));
  };
  const present = visit(type);
  return { complete, present, work };
}

/** Applicability only. Actual proof/check/effect evidence comes from histories. */
export function merkleTargets(program: Program, allowance = 20000): { complete: boolean; applicable: boolean; work: number } {
  let work = 0, exhausted = false;
  const seen = new Set<string>(), pending = [...program.entries];
  const types = new Map<string, boolean>();
  const relevantType = (type: string, depth = 0): boolean => {
    if (++work > allowance || depth > 16) { exhausted = true; return false; }
    if (types.has(type)) return types.get(type)!;
    const term = parseType(program.representationOf(type));
    // representationOf removes the canonical stdlib prefix; user declarations
    // retain their module-qualified identities, even when their names match.
    if (["MerkleTreeDigest", "MerkleTree", "HistoricMerkleTree"].includes(term.name)) return true;
    const fields = program.fieldsOf(type);
    const result = fields ? Object.values(fields).some(field => relevantType(field, depth + 1))
      : ["Map", "Set", "List", "Vector", "$tuple"].includes(term.name) && term.args.some(child => relevantType(printType(child), depth + 1));
    types.set(type, result); return result;
  };
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const symbol = program.symbols.get(id)!;
    const fn = program.functions.get(id);
    if (merkleRootCircuit(id) || relevantType(symbol.type)
      || fn?.declaration.parameters.some(parameter => relevantType(parameter.type))
      || [...fn?.readsState ?? []].some(ledger => relevantType(program.symbols.get(ledger)!.type)))
      return { complete: !exhausted && work <= allowance, applicable: true, work };
    for (const callee of fn?.calls ?? []) pending.push(callee);
  }
  return { complete: !exhausted && work <= allowance, applicable: exhausted, work };
}
