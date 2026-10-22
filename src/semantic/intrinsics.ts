import { standardStructFields, standardStructs, zkir3Structs } from "./stdlib.js";
import { parseType, printType, typeArguments } from "./types.js";
import { STANDARD_EVENTS } from "./events.js";

export interface Intrinsic {
  kind: "hash" | "commitment" | "derived" | "constructor" | "witness";
  arity: number;
  result: string;
  parameters: string[];
  generics?: string;
  requiresNonOpaqueInput?: boolean;
  nativeEffect?: boolean;
  zkir3?: boolean;
}

const intrinsic = (kind: Intrinsic["kind"], parameters: string[], result: string, generics?: string): Intrinsic => ({ kind, arity: parameters.length, parameters, result, generics });

export const INTRINSICS: Record<string, Intrinsic> = {
  persistentHash: { ...intrinsic("hash", ["T"], "Bytes<32>", "<T>"), requiresNonOpaqueInput: true },
  transientHash: intrinsic("hash", ["T"], "Field", "<T>"),
  keccak256: { ...intrinsic("hash", ["T"], "Bytes<32>", "<T>"), requiresNonOpaqueInput: true },
  persistentCommit: { ...intrinsic("commitment", ["T", "Bytes<32>"], "Bytes<32>", "<T>"), requiresNonOpaqueInput: true },
  transientCommit: intrinsic("commitment", ["T", "Field"], "Field", "<T>"),
  degradeToTransient: intrinsic("derived", ["Bytes<32>"], "Field"),
  upgradeFromTransient: intrinsic("derived", ["Field"], "Bytes<32>"),
  some: intrinsic("constructor", ["T"], "Maybe", "<T>"),
  none: intrinsic("constructor", [], "Maybe", "<T>"),
  left: intrinsic("constructor", ["A"], "Either", "<A,B>"),
  right: intrinsic("constructor", ["B"], "Either", "<A,B>"),
  ownPublicKey: intrinsic("witness", [], "ZswapCoinPublicKey"),
  createZswapInput: { ...intrinsic("witness", ["QualifiedShieldedCoinInfo"], "[]"), nativeEffect: true },
  createZswapOutput: { ...intrinsic("witness", ["ShieldedCoinInfo", "Either<ZswapCoinPublicKey,ContractAddress>"], "[]"), nativeEffect: true },
  ecAdd: intrinsic("derived", ["JubjubPoint", "JubjubPoint"], "JubjubPoint"),
  ecNeg: intrinsic("derived", ["JubjubPoint"], "JubjubPoint"),
  ecMul: intrinsic("derived", ["JubjubPoint", "JubjubScalar"], "JubjubPoint"),
  ecMulGenerator: intrinsic("derived", ["JubjubScalar"], "JubjubPoint"),
  jubjubPointX: intrinsic("derived", ["JubjubPoint"], "Field"),
  jubjubPointY: intrinsic("derived", ["JubjubPoint"], "Field"),
  constructJubjubPoint: intrinsic("derived", ["Field", "Field"], "JubjubPoint"),
  hashToCurve: intrinsic("derived", ["T"], "JubjubPoint", "<T>"),
  "neg:Secp256k1Scalar": { ...intrinsic("derived", ["Secp256k1Scalar"], "Secp256k1Scalar"), zkir3: true },
  "neg:Secp256k1Base": { ...intrinsic("derived", ["Secp256k1Base"], "Secp256k1Base"), zkir3: true },
  "inv:Secp256k1Scalar": { ...intrinsic("derived", ["Secp256k1Scalar"], "Secp256k1Scalar"), zkir3: true },
  "inv:Secp256k1Base": { ...intrinsic("derived", ["Secp256k1Base"], "Secp256k1Base"), zkir3: true },
  secp256k1PointX: { ...intrinsic("derived", ["Secp256k1Point"], "Secp256k1Base"), zkir3: true },
  secp256k1PointY: { ...intrinsic("derived", ["Secp256k1Point"], "Secp256k1Base"), zkir3: true },
  "ecAdd:Secp256k1": { ...intrinsic("derived", ["Secp256k1Point", "Secp256k1Point"], "Secp256k1Point"), zkir3: true },
  "ecMul:Secp256k1": { ...intrinsic("derived", ["Secp256k1Point", "Secp256k1Scalar"], "Secp256k1Point"), zkir3: true },
  "ecMulGenerator:Secp256k1": { ...intrinsic("derived", ["Secp256k1Scalar"], "Secp256k1Point"), zkir3: true },
};

/** Use the selected canonical overload, never the name shared by overloads. */
export function intrinsicModel(symbol: { id: string; intrinsicProfile?: "legacy" }): Intrinsic {
  const model = INTRINSICS[symbol.id.slice("intrinsic::".length)];
  if (symbol.intrinsicProfile === "legacy" && ["intrinsic::ecMul", "intrinsic::ecMulGenerator"].includes(symbol.id)) return { ...model, parameters: model.parameters.map(type => type === "JubjubScalar" ? "Field" : type) };
  return model;
}

export const STANDARD_TYPES = { ...standardStructFields, ...Object.fromEntries(Object.entries(STANDARD_EVENTS).map(([name, event]) => [name, event.fields])) };

export interface StandardType {
  generics?: string;
  ledger?: boolean;
  ordinaryArguments?: number[];
  zkir3?: boolean;
}

export const STANDARD_TYPE_MODELS: Record<string, StandardType> = {
  ...Object.fromEntries(Object.keys(STANDARD_EVENTS).map(name => [name, {}])),
  ...Object.fromEntries(standardStructs.map(declaration => [declaration.name, { generics: declaration.generics }])),
  ...Object.fromEntries(zkir3Structs.map(declaration => [declaration.name, { generics: declaration.generics, zkir3: true }])),
  JubjubPoint: {},
  JubjubScalar: {},
  Secp256k1Base: { zkir3: true },
  Secp256k1Scalar: { zkir3: true },
  Secp256k1Point: { zkir3: true },
  Counter: { ledger: true },
  Kernel: { ledger: true },
  Map: { generics: "<K,V>", ledger: true, ordinaryArguments: [0] },
  Set: { generics: "<T>", ledger: true, ordinaryArguments: [0] },
  List: { generics: "<T>", ledger: true, ordinaryArguments: [0] },
  MerkleTree: { generics: "<#N,T>", ledger: true, ordinaryArguments: [1] },
  HistoricMerkleTree: { generics: "<#N,T>", ledger: true, ordinaryArguments: [1] },
};

export function standardTypeName(identity: string): string | undefined {
  const name = identity.startsWith("standard-type::") ? identity.slice("standard-type::".length) : undefined;
  return name && Object.hasOwn(STANDARD_TYPE_MODELS, name) ? name : undefined;
}

export function standardType(text: string): string {
  const term = parseType(text);
  if (Object.hasOwn(STANDARD_TYPE_MODELS, term.name)) term.name = `standard-type::${term.name}`;
  term.args = term.args.map(arg => parseType(standardType(printType(arg))));
  return printType(term);
}

export function intrinsicResult(symbol: { id: string }, generics: string | undefined, args: string[]): string {
  const result = intrinsicModel(symbol).result;
  if (!["Maybe", "Either"].includes(result)) return result;
  const parameters = typeArguments(generics);
  if (!parameters.length && result === "Maybe" && args[0]) parameters.push(args[0]);
  return `${result}<${parameters.join(",")}>`;
}

export interface LedgerEffect {
  reads: boolean;
  writes: boolean;
  arity: number;
  parameters: string[];
  result: string;
  region: boolean;
  publicArguments?: number[];
  coinArgument?: number;
}

export function ledgerEffect(type: string, operation: string, qualifiedCoin = false): LedgerEffect | undefined {
  const term = parseType(type);
  const key = term.args[0] ? printType(term.args[0]) : "unknown";
  const value = term.args[1] ? printType(term.args[1]) : "unknown";
  const effect = (parameters: string[], result: string, writes = false, reads = true, region = false): LedgerEffect => ({ arity: parameters.length, parameters, result, writes, reads, region });
  // Qualified coin writes first look up the transaction's allocated Merkle index.
  // The semantic layer authenticates the stored type, including structural aliases.
  const coinWrite = term.name === "Map" || term.name === "Set" ? "insertCoin" : term.name === "List" ? "pushFrontCoin" : "writeCoin";
  if (qualifiedCoin && operation === coinWrite) {
    const parameters = ["ShieldedCoinInfo", "Either<ZswapCoinPublicKey,ContractAddress>"];
    return { ...effect(term.name === "Map" ? [key, ...parameters] : parameters, "[]", true, ["Map", "Set", "List"].includes(term.name)), coinArgument: term.name === "Map" ? 1 : 0 };
  }
  // compactc-v0.34.0 midnight-ledger.ss Kernel declarations. These operations
  // observe invocation context or append transaction effects, not Cell storage.
  if (term.name === "Kernel") {
    const token = "Either<Bytes<32>,Bytes<32>>";
    if (operation === "self") return effect([], "ContractAddress");
    if (operation === "balance") return effect([token], "Uint<128>");
    if (["balanceLessThan", "balanceGreaterThan"].includes(operation)) return effect([token, "Uint<128>"], "Boolean");
    if (["blockTimeLessThan", "blockTimeGreaterThan"].includes(operation)) return effect(["Uint<64>"], "Boolean");
    if (["claimZswapNullifier", "claimZswapCoinSpend", "claimZswapCoinReceive"].includes(operation)) return effect(["Bytes<32>"], "[]", true, false);
    if (operation === "claimContractCall") return { ...effect(["Bytes<32>", "Bytes<32>", "Field"], "[]", true, false), publicArguments: [0, 1] };
    if (operation === "checkpoint") return effect([], "[]", true, false);
    if (["mintShielded", "mintUnshielded"].includes(operation)) return effect(["Bytes<32>", "Uint<64>"], "[]", true, false);
    if (operation === "claimUnshieldedCoinSpend") return effect([token, "Either<ContractAddress,UserAddress>", "Uint<128>"], "[]", true, false);
    if (["incUnshieldedInputs", "incUnshieldedOutputs"].includes(operation)) return effect([token, "Uint<128>"], "[]", true, false);
    return undefined;
  }
  if (["MerkleTree", "HistoricMerkleTree"].includes(term.name)) {
    if (operation === "checkRoot") return effect(["MerkleTreeDigest"], "Boolean");
    if (operation === "isFull") return effect([], "Boolean");
    if (operation === "resetToDefault") return effect([], "[]", true, false);
    if (operation === "resetHistory" && term.name === "HistoricMerkleTree") return effect([], "[]", true);
    if (["insert", "insertHash"].includes(operation)) return effect([operation === "insert" ? value : "Bytes<32>"], "[]", true);
    if (["insertIndex", "insertHashIndex"].includes(operation)) return effect([operation === "insertIndex" ? value : "Bytes<32>", "Uint<64>"], "[]", true);
    if (operation === "insertIndexDefault") return effect(["Uint<64>"], "[]", true);
    return undefined;
  }
  if (term.name === "Counter") {
    if (["increment", "decrement"].includes(operation)) return effect(["Uint<16>"], "[]", true, false);
    if (operation === "lessThan") return effect(["Uint<64>"], "Boolean");
    if (operation === "read") return effect([], "Uint<64>");
    if (operation === "resetToDefault") return effect([], "[]", true, false);
  }
  if (term.name === "Map") {
    if (operation === "lookup") return effect([key], value, false, true, true);
    if (operation === "member") return effect([key], "Boolean");
    if (operation === "insert") return effect([key, value], "[]", true);
    if (["remove", "insertDefault"].includes(operation)) return effect([key], "[]", true);
  }
  if (term.name === "Set") {
    if (operation === "member") return effect([key], "Boolean");
    if (["insert", "remove"].includes(operation)) return effect([key], "[]", true);
  }
  if (term.name === "List") {
    if (operation === "pushFront") return effect([key], "[]", true);
    if (operation === "popFront") return effect([], "[]", true);
    if (operation === "head") return effect([], `Maybe<${key}>`);
    if (operation === "length") return effect([], "Uint<64>");
  }
  if (["Map", "Set", "List"].includes(term.name)) {
    if (operation === "size" && term.name !== "List") return effect([], "Uint<64>");
    if (operation === "isEmpty") return effect([], "Boolean");
    if (operation === "resetToDefault") return effect([], "[]", true, false);
  }
  if (["Counter", "Map", "Set", "List", "MerkleTree", "HistoricMerkleTree", "Kernel"].includes(term.name)) return undefined;
  if (operation === "read") return effect([], type);
  if (operation === "write") return effect([type], "[]", true, false);
  if (operation === "resetToDefault") return effect([], "[]", true, false);
  return undefined;
}
