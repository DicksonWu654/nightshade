import { validateSourceMapGetters, type SourceMapGetterPolicy } from "./semantic/source-map-getters.js";
import { validateSourceClaims, type SourceClaimPolicy } from "./semantic/source-claims.js";
import { resolveOperationIntent, validateOperationIntent, type OperationIntentPolicy, type ResolvedOperationIntentPolicy } from "./semantic/operation-intent.js";
import type { Flow, PublicSink } from "./dataflow/index.js";
import { Span, fail } from "./model.js";
import { Program, SymbolInfo } from "./semantic/index.js";
import { naturalValue, parseType, printType } from "./semantic/types.js";
import { containsMerkleTree } from "./semantic/merkle-targets.js";
import { STANDARD_TYPE_MODELS } from "./semantic/intrinsics.js";

export const BUILTIN_POLICIES = ["openzeppelin-ownable", "openzeppelin-access-control", "openzeppelin-pausable", "openzeppelin-initializable"] as const;
export type BuiltinPolicy = typeof BUILTIN_POLICIES[number];

export interface Policies {
  sourceMapGetters?: SourceMapGetterPolicy[];
  sourceClaims?: SourceClaimPolicy[];
  operationIntent?: OperationIntentPolicy[];
  builtins?: BuiltinPolicy[];
  secrets?: { witness?: string; circuit?: string; parameter?: string; allowedForms?: Flow["form"][]; sinkKinds?: PublicSink["kind"][] }[];
  authorization?: { state: string; guard: string }[];
  transitions?: { state: string; from: string; to: string }[];
  workBudgets?: { circuit: string; maxUnits: number }[];
  /** The selected consumer must serve metadata for the current NFT incarnation. */
  currentNftMetadata?: { owners: string; metadata: string; consumer: string }[];
  /** The pinned Ownable owner guard must remain usable with this stored owner. */
  callableOwnable?: { owner: string }[];
  /** Successful amount-zero invocations should not require an initial Map entry. */
  zeroAmountMembership?: { circuit: string; amount: string; map: string }[];
  /** Enforced positive native membership checks must use the current root at guard time. */
  currentRootMembership?: { circuit: string; ledger: string }[];
  /** Complete ordinary Cell co-updates must not expose partial/mixed revisions. */
  atomicUpdates?: { circuit: string; ledgers: string[] }[];
}

export interface ResolvedPolicies {
  sourceMapGetters?: SourceMapGetterPolicy[];
  sourceClaims?: SourceClaimPolicy[];
  operationIntent?: ResolvedOperationIntentPolicy[];
  builtins?: BuiltinPolicy[];
  secrets: { symbol: string; allowedForms: Flow["form"][]; sinkKinds?: PublicSink["kind"][] }[];
  authorization: { state: string; guard: string }[];
  transitions: { state: string; from: string; to: string }[];
  workBudgets: { circuit: string; maxUnits: number }[];
  currentNftMetadata?: { owners: string; metadata: string; consumer: string }[];
  callableOwnable?: { owner: string }[];
  zeroAmountMembership?: { circuit: string; amount: string; map: string }[];
  currentRootMembership?: { circuit: string; ledger: string }[];
  atomicUpdates?: { circuit: string; ledgers: string[] }[];
}

const SECRET_SINK_KINDS: readonly PublicSink["kind"][] = ["ledger-write", "exported-return", "ledger-operation", "event"];

/** Absence retains the historical all-sink privacy contract. Validate again at
 * direct policy resolution, which need not pass through JSON configuration. */
function secretSinkKinds(value: unknown, code: string, location: Span): PublicSink["kind"][] | undefined {
  if (value === undefined) return;
  const invalid = () => fail(code, "Secret sinkKinds requires a nonempty dense array of at most four unique public sink kinds: ledger-write, exported-return, ledger-operation, event", location);
  if (!Array.isArray(value) || value.length < 1 || value.length > SECRET_SINK_KINDS.length
    || Reflect.ownKeys(value).length !== value.length + 1) return invalid();
  const selected: PublicSink["kind"][] = [];
  for (let index = 0; index < value.length; index++) {
    const item = Object.getOwnPropertyDescriptor(value, index);
    if (!item || !("value" in item) || !item.enumerable || !SECRET_SINK_KINDS.includes(item.value)
      || selected.includes(item.value)) return invalid();
    selected.push(item.value);
  }
  return selected;
}

export function resolvePolicies(program: Program, policies: Policies = {}): ResolvedPolicies {
  const location = program.rootSource.ast.span;
  const mapGetterDescriptor = Object.getOwnPropertyDescriptor(policies, "sourceMapGetters");
  if ("sourceMapGetters" in policies && (!mapGetterDescriptor || !("value" in mapGetterDescriptor) || !mapGetterDescriptor.enumerable))
    fail("invalid-policy", "sourceMapGetters must be an enumerable data property", location);
  const sourceClaimsDescriptor = Object.getOwnPropertyDescriptor(policies, "sourceClaims");
  if ("sourceClaims" in policies && (!sourceClaimsDescriptor || !("value" in sourceClaimsDescriptor) || !sourceClaimsDescriptor.enumerable))
    fail("invalid-policy", "sourceClaims must be an enumerable data property", location);
  if (policies.atomicUpdates && (!Array.isArray(policies.atomicUpdates) || policies.atomicUpdates.length > 64
    || Object.keys(policies.atomicUpdates).length !== policies.atomicUpdates.length
    || Array.from(policies.atomicUpdates).some(policy => !policy)))
    fail("invalid-policy", "Atomic update policies require a dense array of at most 64 groups", location);
  const select = (name: string, kinds: SymbolInfo["kind"][]): SymbolInfo => {
    const candidates = program.activeSymbols().filter(symbol => kinds.includes(symbol.kind) && (symbol.id === name || symbol.name === name));
    if (candidates.length !== 1) fail("invalid-policy", `Policy selector ${name} resolves to ${candidates.length} ${kinds.join("/")} symbols; use an unambiguous symbol ID`, location);
    return candidates[0];
  };
  const constant = (text: string, state: SymbolInfo): string => {
    const representation = program.representationOf(state.type);
    if (text === "*") return text;
    if (representation === "Boolean" && ["true", "false"].includes(text)) return `boolean:${text}`;
    if (/^(Field|Uint<)/.test(representation) && naturalValue(text) !== undefined) return `integer:${naturalValue(text)}`;
    const enumeration = program.symbols.get(representation);
    const variant = text.split(".").at(-1)!;
    if (enumeration?.declaration?.typeKind === "enum" && enumeration.declaration.variants?.includes(variant) && (!text.includes(".") || text === `${enumeration.name}.${variant}`)) return `enum:${enumeration.name}.${variant}`;
    return fail("invalid-policy", `${text} is not a supported value of state ${state.name}`, state.span);
  };
  return {
    ...("sourceMapGetters" in policies ? { sourceMapGetters: validateSourceMapGetters(policies.sourceMapGetters, location, "invalid-policy") } : {}),
    ...(policies.sourceClaims !== undefined ? { sourceClaims: validateSourceClaims(policies.sourceClaims, location, "invalid-policy") } : {}),
    ...(policies.operationIntent ? { operationIntent: resolveOperationIntent(program, policies.operationIntent) } : {}),
    ...(policies.atomicUpdates?.length ? { atomicUpdates: [...new Map(policies.atomicUpdates.map(policy => {
      if (!policy || !Array.isArray(policy.ledgers) || policy.ledgers.length < 2 || policy.ledgers.length > 16
        || Object.keys(policy.ledgers).length !== policy.ledgers.length
        || Array.from(policy.ledgers).some(name => typeof name !== "string" || !name.length))
        fail("invalid-policy", "Atomic update groups require two to sixteen ordinary Cell selectors", location);
      const circuit = select(policy.circuit, ["circuit"]);
      program.ensureFunction(circuit.id);
      if (!program.entries.includes(circuit.id)) fail("invalid-policy", "Atomic update policy requires an exported entry circuit", circuit.span);
      const ledgers = policy.ledgers.map(name => select(name, ["ledger"]));
      if (new Set(ledgers.map(ledger => ledger.id)).size !== ledgers.length)
        fail("invalid-policy", "Atomic update groups require distinct canonical ledger fields", circuit.span);
      for (const ledger of ledgers) if (STANDARD_TYPE_MODELS[parseType(program.representationOf(ledger.type)).name]?.ledger)
        fail("invalid-policy", "Atomic update groups support ordinary Cells, not native ledger ADTs", ledger.span);
      const resolved = { circuit: circuit.id, ledgers: ledgers.map(ledger => ledger.id).sort() };
      return [JSON.stringify(resolved), resolved] as const;
    })).values()] } : {}),
    ...(policies.currentRootMembership?.length ? { currentRootMembership: [...new Map(policies.currentRootMembership.map(policy => {
      const circuit = select(policy.circuit, ["circuit"]), ledger = select(policy.ledger, ["ledger"]);
      program.ensureFunction(circuit.id);
      const target = containsMerkleTree(program, ledger.type);
      if (!program.entries.includes(circuit.id) || !target.complete || !target.present)
        fail("invalid-policy", "Current-root membership requires an exported circuit and a ledger containing canonical native Merkle trees within the selector allowance", circuit.span);
      return [JSON.stringify([circuit.id, ledger.id]), { circuit: circuit.id, ledger: ledger.id }] as const;
    })).values()] } : {}),
    ...(policies.zeroAmountMembership?.length ? { zeroAmountMembership: [...new Map(policies.zeroAmountMembership.map(policy => {
      const circuit = select(policy.circuit, ["circuit"]), map = select(policy.map, ["ledger"]);
      program.ensureFunction(circuit.id);
      const amount = circuit.declaration!.parameters.find(parameter => parameter.name === policy.amount || parameter.symbol === policy.amount);
      if (!program.entries.includes(circuit.id) || !amount || !/^(Field|Uint<\d+>)$/.test(program.representationOf(amount.type)))
        fail("invalid-policy", "Zero amount membership requires an exported circuit and scalar numeric input", circuit.span);
      if (parseType(program.representationOf(map.type)).name !== "Map") fail("invalid-policy", "Zero amount membership requires a root Map ledger", map.span);
      return [JSON.stringify([circuit.id, amount!.symbol!, map.id]), { circuit: circuit.id, amount: amount!.symbol!, map: map.id }] as const;
    })).values()] } : {}),
    ...(policies.builtins?.length ? { builtins: [...new Set(policies.builtins)] } : {}),
    ...(policies.callableOwnable?.length ? { callableOwnable: [...new Map(policies.callableOwnable.map(policy => {
      const owner = select(policy.owner, ["ledger"]);
      const shape = parseType(program.representationOf(owner.type));
      if (program.nativeTypeOf(owner.type) !== "Either" || shape.args.length !== 2
        || program.representationOf(printType(shape.args[0])) !== "Bytes<32>"
        || program.nativeTypeOf(printType(shape.args[1])) !== "ContractAddress")
        fail("invalid-policy", "Callable Ownable requires a root native Either<Bytes<32>, ContractAddress> owner ledger", owner.span);
      return [owner.id, { owner: owner.id }] as const;
    })).values()] } : {}),
    ...(policies.currentNftMetadata?.length ? { currentNftMetadata: policies.currentNftMetadata.map(policy => {
      const owners = select(policy.owners, ["ledger"]), metadata = select(policy.metadata, ["ledger"]);
      const consumer = select(policy.consumer, ["circuit"]);
      program.ensureFunction(consumer.id);
      const shape = parseType(program.representationOf(metadata.type));
      if (shape.name !== "Map" || shape.args.length !== 2
        || program.representationOf(printType(shape.args[0])) !== "Uint<128>"
        || program.representationOf(printType(shape.args[1])) !== 'Opaque<"string">')
        fail("invalid-policy", "Current NFT metadata requires a root Map<Uint<128>, Opaque<\"string\">>", metadata.span);
      if (!program.entries.includes(consumer.id) || program.representationOf(consumer.type) !== 'Opaque<"string">')
        fail("invalid-policy", "Current NFT metadata consumer must be an exported Opaque<\"string\"> circuit", consumer.span);
      if (owners.id === metadata.id) fail("invalid-policy", "NFT ownership and auxiliary metadata must be separate ledgers", metadata.span);
      return { owners: owners.id, metadata: metadata.id, consumer: consumer.id };
    }) } : {}),
    secrets: (policies.secrets ?? []).map(policy => {
      const selectedSinks = secretSinkKinds(policy.sinkKinds, "invalid-policy", location);
      const sinkSelection = selectedSinks ? { sinkKinds: selectedSinks } : {};
      if (policy.witness) return { symbol: select(policy.witness, ["witness"]).id, allowedForms: policy.allowedForms ?? [], ...sinkSelection };
      const circuit = select(policy.circuit!, ["circuit", "constructor"]);
      const parameter = circuit.declaration!.parameters.find(item => item.name === policy.parameter);
      if (!program.entries.includes(circuit.id) || !parameter) fail("invalid-policy", `Secret input ${policy.circuit}.${policy.parameter} must be an entrypoint parameter`, location);
      return { symbol: parameter.symbol!, allowedForms: policy.allowedForms ?? [], ...sinkSelection };
    }),
    authorization: (policies.authorization ?? []).map(policy => {
      const state = select(policy.state, ["ledger"]);
      const guard = select(policy.guard, ["circuit"]);
      if (program.representationOf(guard.type) !== "[]") fail("invalid-policy", `Required guard ${guard.name} must return []; a Boolean result alone is not authorization`, guard.span);
      return { state: state.id, guard: guard.id };
    }),
    transitions: (policies.transitions ?? []).map(policy => {
      const state = select(policy.state, ["ledger"]);
      const representation = program.representationOf(state.type);
      if (representation !== "Boolean" && !/^(Field|Uint<)/.test(representation) && program.symbols.get(representation)?.declaration?.typeKind !== "enum") fail("invalid-policy", `Transition policies require scalar Boolean, numeric or enum state, not ${state.type}`, state.span);
      return { state: state.id, from: constant(policy.from, state), to: constant(policy.to, state) };
    }),
    workBudgets: (policies.workBudgets ?? []).map(policy => {
      const circuit = select(policy.circuit, ["circuit", "constructor"]);
      program.ensureFunction(circuit.id);
      return { circuit: circuit.id, maxUnits: policy.maxUnits };
    }),
  };
}

export function validatePolicies(value: unknown, location: Span): Policies {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid-config", "policies must be an object", location);
  const object = value as Record<string, unknown>;
  const mapGetterDescriptor = Object.getOwnPropertyDescriptor(object, "sourceMapGetters");
  if ("sourceMapGetters" in object && (!mapGetterDescriptor || !("value" in mapGetterDescriptor) || !mapGetterDescriptor.enumerable))
    fail("invalid-config", "sourceMapGetters must be an enumerable data property", location);
  const sourceClaimsDescriptor = Object.getOwnPropertyDescriptor(object, "sourceClaims");
  if ("sourceClaims" in object && (!sourceClaimsDescriptor || !("value" in sourceClaimsDescriptor) || !sourceClaimsDescriptor.enumerable))
    fail("invalid-config", "sourceClaims must be an enumerable data property", location);
  const fields: Record<string, string[]> = { secrets: ["witness", "circuit", "parameter", "allowedForms", "sinkKinds"], authorization: ["state", "guard"], transitions: ["state", "from", "to"], workBudgets: ["circuit", "maxUnits"], currentNftMetadata: ["owners", "metadata", "consumer"], callableOwnable: ["owner"], zeroAmountMembership: ["circuit", "amount", "map"], currentRootMembership: ["circuit", "ledger"], atomicUpdates: ["circuit", "ledgers"] };
  for (const [key, entries] of Object.entries(object)) {
    if (key === "sourceMapGetters") { validateSourceMapGetters(entries, location, "invalid-config"); continue; }
    if (key === "sourceClaims") { validateSourceClaims(entries, location, "invalid-config"); continue; }
    if (key === "operationIntent") { validateOperationIntent(entries, location, "invalid-config"); continue; }
    if (key === "builtins") {
      if (!Array.isArray(entries) || entries.length > BUILTIN_POLICIES.length || Object.keys(entries).length !== entries.length || Array.from(entries).some(item => !BUILTIN_POLICIES.includes(item))) fail("invalid-config", "Unknown built-in policy", location);
      continue;
    }
    if (!fields[key] || !Array.isArray(entries)) fail("invalid-config", `Unknown policy or invalid array: ${key}`, location);
    if (key === "atomicUpdates" && (entries.length > 64 || Object.keys(entries).length !== entries.length))
      fail("invalid-config", "Atomic update policies require a dense array of at most 64 groups", location);
    if (key === "currentRootMembership" && (entries.length > 64 || Object.keys(entries).length !== entries.length))
      fail("invalid-config", "Current-root policies require a dense array of at most 64 entries", location);
    if (key === "currentNftMetadata" && (entries.length > 64 || Object.keys(entries).length !== entries.length))
      fail("invalid-config", "Current NFT metadata policies require a dense array of at most 64 relations", location);
    if ((key === "callableOwnable" || key === "zeroAmountMembership") && (entries.length > 64 || Object.keys(entries).length !== entries.length))
      fail("invalid-config", "Callable Ownable policies require a dense array of at most 64 owners", location);
    for (const entry of entries) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry) || Object.keys(entry).some(field => !fields[key].includes(field))) fail("invalid-config", `Invalid ${key} policy`, location);
      const policy = entry as Record<string, unknown>;
      for (const [field, item] of Object.entries(policy)) if (!["allowedForms", "sinkKinds", "maxUnits", ...(key === "atomicUpdates" ? ["ledgers"] : [])].includes(field) && (typeof item !== "string" || !item.length)) fail("invalid-config", `Invalid ${key}.${field}`, location);
      if (key === "atomicUpdates" && (!Array.isArray(policy.ledgers) || policy.ledgers.length < 2 || policy.ledgers.length > 16
        || Object.keys(policy.ledgers).length !== policy.ledgers.length
        || Array.from(policy.ledgers).some(name => typeof name !== "string" || !name.length)
        || new Set(policy.ledgers).size !== policy.ledgers.length))
        fail("invalid-config", "Atomic update groups require two to sixteen distinct nonempty Cell selectors", location);
      if (key === "secrets") {
        secretSinkKinds(policy.sinkKinds, "invalid-config", location);
        if (!(Boolean(policy.witness) !== Boolean(policy.circuit && policy.parameter)) || policy.witness && (policy.circuit || policy.parameter)) fail("invalid-config", "Secret policy requires witness OR circuit and parameter", location);
        if (policy.allowedForms !== undefined && (!Array.isArray(policy.allowedForms) || policy.allowedForms.some(form => !["raw", "derived", "hash", "commitment"].includes(form)))) fail("invalid-config", "Invalid allowedForms", location);
      } else for (const field of fields[key]) if (!(field in policy)) fail("invalid-config", `Missing ${key}.${field}`, location);
      if (key === "workBudgets" && (!Number.isSafeInteger(policy.maxUnits) || Number(policy.maxUnits) < 1)) fail("invalid-config", "maxUnits must be a positive safe integer", location);
    }
  }
  return object as Policies;
}
