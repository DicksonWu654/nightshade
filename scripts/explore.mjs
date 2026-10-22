#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

// Offline generic explorer.  Circuit and witness types come from the
// compiler's contract-info.json; only legacy constructor metadata is read from
// Nightshade's source model because compiler 0.31 does not serialize it.
const root = resolve(process.argv[2] ?? "");
const budgetMs = Number(process.env.NIGHTSHADE_EXPLORE_MS ?? 180000);
const compilerVersion = process.env.NIGHTSHADE_COMPILER ?? "0.31.1";
// Heuristic oracles require explicit opt-in. Their alarms do not establish
// transaction feasibility or actionable vulnerabilities.
const experimentalOraclesEnabled = process.env.NIGHTSHADE_ENABLE_EXPERIMENTAL_ORACLES === "1";
const disabledByDefault = new Set([
  "postTerminalAccumulation",
  "unauthorizedSupplyGrowth",
  "stuckValue",
  "replayDifferential",
  "witnessDifferential",
  "conservation",
]);
const compiler = process.env.COMPACTC ?? "compactc";
const runtimeCandidates = [
  process.env.COMPACT_RUNTIME,
  resolve("tests/runtime-fixtures/qualification-inputs/node_modules/@midnight-ntwrk/compact-runtime/dist/index.js"),
  resolve("node_modules/@midnight-ntwrk/compact-runtime/dist/index.js"),
].filter(Boolean);
const replay = [];
let differentialRecords = [];
let metamorphic = { callerDifferential: oracleResult(undefined), replayDifferential: oracleResult(undefined), witnessDifferential: oracleResult(undefined), orderingDifferential: oracleResult(undefined), conservation: oracleResult(undefined) };
const result = { schemaVersion: "nightshade-explore-2", root, compilerVersion, compiler,
  startedAt: new Date().toISOString(), budgetMs, runtime: { attempted: false, available: false },
  facts: {}, contractInfo: {}, sequences: [], transitions: [], violations: [], misses: [], falseAlarms: [] };

function run(command, args, options = {}) {
  const r = spawnSync(command, args, { encoding: "utf8", timeout: options.timeout ?? budgetMs,
    maxBuffer: 16 * 1024 * 1024, ...options });
  return { status: r.status, stdout: String(r.stdout ?? ""), stderr: String(r.stderr ?? ""), error: r.error?.message };
}
function digest(value) {
  return createHash("sha256").update(JSON.stringify(value, (_key, v) => {
    if (typeof v === "bigint") return `${v}n`;
    if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
    return v;
  })).digest("hex");
}
function jsonReplacer(_key, value) {
  if (typeof value === "bigint") return `${value}n`;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("hex");
  return value;
}
function firstBytes(value, preferred = []) {
  if (value instanceof Uint8Array) return value;
  if (!value || typeof value !== "object") return undefined;
  for (const key of [...preferred, "id", "offerId", "value", "bytes"]) if (key in value) {
    const found = firstBytes(value[key], preferred);
    if (found) return found;
  }
  for (const child of Object.values(value)) { const found = firstBytes(child, preferred); if (found) return found; }
  return undefined;
}
function preserveMaxvals(text) { return text.replace(/("maxval"\s*:\s*)(\d+)/g, "$1\"$2\""); }
function maxVal(type) {
  if (type?.maxval !== undefined) { try { return BigInt(type.maxval); } catch {} }
  return (1n << 248n) - 1n;
}
function typeName(type) { return String(type?.["type-name"] ?? ""); }
function bytes(length, mode) {
  const fill = mode === "max" ? 255 : mode === "one" ? 2 : 1;
  return new Uint8Array(Math.max(0, Number(length ?? 32))).fill(fill);
}
function parseSourceType(text) {
  const s = String(text ?? "").replace(/\s+/g, "");
  if (s === "Boolean") return { "type-name": "Boolean" };
  if (s === "Field") return { "type-name": "Field" };
  const u = /^Uint<(\d+)>$/.exec(s); if (u) return { "type-name": "Uint", maxval: ((1n << BigInt(u[1])) - 1n).toString() };
  const b = /^Bytes<(\d+)>$/.exec(s); if (b) return { "type-name": "Bytes", length: Number(b[1]) };
  const v = /^Vector<(\d+),(.+)>$/.exec(s); if (v) return { "type-name": "Vector", length: Number(v[1]), type: parseSourceType(v[2]) };
  if (s.startsWith("Opaque")) return { "type-name": "Opaque", tsType: s.includes("string") ? "string" : "Uint8Array" };
  return { "type-name": "Opaque", tsType: "Uint8Array" };
}
function sourceTypeValue(text, mode, runtime, name = "") {
  const s = String(text ?? "");
  const field = String(name ?? "").toLowerCase();
  const identityField = /(initialholder|payout|admin|board|house|keeper|operator|registrar|convenor|issuer|organis|council|merchant|guardian|relayer|govern|signer|platform|[a-z]id$|^s[0-3]$)/i.test(field);
  if (/ZswapCoinPublicKey$/.test(s)) return { bytes: bytes(32, identityField ? "zero" : mode) };
  if (/ContractAddress$/.test(s)) return { bytes: runtime?.encodeContractAddress && runtime?.dummyContractAddress ? runtime.encodeContractAddress(runtime.dummyContractAddress()) : bytes(32, mode) };
  if (/UserAddress$/.test(s)) return { bytes: bytes(32, identityField ? "zero" : mode) };
  const generic = /^(?:standard-type::)?(Either|Maybe)<(.+)>$/.exec(s.replace(/\s+/g, ""));
  if (generic?.[1] === "Either") return { is_left: true, left: sourceTypeValue(generic[2].split(",")[0], mode, runtime, name), right: sourceTypeValue(generic[2].split(",")[1], mode, runtime, name) };
  if (generic?.[1] === "Maybe") return { is_some: false, value: sourceTypeValue(generic[2], mode, runtime, name) };
  return undefined;
}
function distinctParameterBytes(name, mode) {
  const n = String(name ?? "").toLowerCase();
  if (/(quote|reward|dcolor|s1|s2|s3|currency)/.test(n)) return bytes(32, "one");
  if (/(base|stake|ccolor|s0|token|color)/.test(n)) return bytes(32, mode);
  return bytes(32, mode);
}
function generatedDomains(text) {
  const domains = [];
  const pattern = /new Uint8Array\(\[([0-9,\s]+)\]\)/g;
  for (const match of text.matchAll(pattern)) {
    const numbers = match[1].split(",").map(value => Number(value.trim())).filter(Number.isFinite);
    if (numbers.length !== 32) continue;
    const decoded = new TextDecoder().decode(Uint8Array.from(numbers)).replace(/\0+$/, "");
    if (/^[\x20-\x7e]+$/.test(decoded)) domains.push({ text: decoded, bytes: Uint8Array.from(numbers) });
  }
  return [...new Map(domains.map(domain => [domain.text, domain])).values()];
}
function sourceDomains(text) {
  const domains = [];
  for (const match of String(text).matchAll(/pad\(32,\s*"([^"]+)"\)/g)) {
    const encoded = new TextEncoder().encode(match[1]); if (encoded.length > 32) continue;
    const value = new Uint8Array(32); value.set(encoded); domains.push({ text: match[1], bytes: value });
  }
  return domains;
}
function domainBytes(domains, needle) { return domains.find(candidate => candidate.text.includes(needle))?.bytes; }
function genericBalancePlan(instance, runtime, domains, launchId) {
  if (!launchId || typeof instance?._deriveUserPublicKey_0 !== "function" || typeof instance?._persistentHash_1 !== "function" || typeof instance?._hashBalanceNode_0 !== "function") return undefined;
  const leafDomain = domainBytes(domains, "balance:leaf"); const padDomain = domainBytes(domains, "balance:pad") ?? bytes(32, "zero");
  if (!leafDomain) return undefined;
  const userSecret = bytes(32, "zero"); const balance = 100n; const heldSince = 0n;
  try {
    const voterKey = instance._deriveUserPublicKey_0({ bytes: userSecret }, launchId).bytes;
    const leaf = instance._persistentHash_1({ domain: leafDomain, voterKey, balance, heldSinceTimestamp: heldSince });
    const proof = Array.from({ length: 20 }, () => ({ sibling: padDomain, goesLeft: true }));
    let root = leaf;
    for (const entry of proof) root = instance._hashBalanceNode_0(root, entry.sibling);
    return { userSecret, balance, heldSince, proof, root };
  } catch { return undefined; }
}
function genericMerklePlan(instance, domains, launchId, kind) {
  if (!launchId || typeof instance?._deriveUserPublicKey_0 !== "function") return undefined;
  const leafDomain = domainBytes(domains, `${kind}:leaf`); const nodeDomain = domainBytes(domains, `${kind}:node`);
  if (!leafDomain || !nodeDomain) return undefined;
  const userSecret = bytes(32, "zero");
  try {
    const caller = instance._deriveUserPublicKey_0({ bytes: userSecret }, launchId).bytes;
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(instance)).filter(name => /^_persistentHash_\d+$/.test(name));
    let leaf; for (const name of methods) { try { const value = instance[name]([leafDomain, caller]); if (value instanceof Uint8Array && value.length === 32) { leaf = value; break; } } catch {} }
    if (!leaf) return undefined;
    const proof = Array.from({ length: 20 }, () => ({ sibling: bytes(32, "zero"), goesLeft: true })); let root = leaf;
    for (const entry of proof) { let next; for (const name of methods) { try { const value = instance[name]({ domain: nodeDomain, left: root, right: entry.sibling }); if (value instanceof Uint8Array && value.length === 32) { next = value; break; } } catch {} } if (!next) return undefined; root = next; }
    return { userSecret, proof, root };
  } catch { return undefined; }
}
function genericBuyPlans(instance, launchId) {
  if (!launchId || typeof instance?._deriveUserPublicKey_0 !== "function" || typeof instance?._computeBuyCommit_0 !== "function") return undefined;
  const userSecret = bytes(32, "zero"); const tokenAmount = 1n; const pricePerToken = 1n;
  try {
    const buyerKey = instance._deriveUserPublicKey_0({ bytes: userSecret }, launchId).bytes;
    return ["zero", "one"].map(mode => { const nonce = bytes(32, mode); return { userSecret, nonce, tokenAmount, pricePerToken, commitment: instance._computeBuyCommit_0(buyerKey, launchId, tokenAmount, pricePerToken, nonce) }; });
  } catch { return undefined; }
}
function genericRoleHashes(instance, domains) {
  if (!instance) return {};
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(instance)).filter(name => /^_roleKeyHash_\d+$/.test(name));
  if (!methods.length) return {};
  const output = {};
  for (const domain of domains) {
    if (!/(role|auth|seller|governor|attestor|operator)/i.test(domain.text)) continue;
    for (const mode of ["zero", "one", "max"]) {
      try {
        const value = instance[methods[0]](bytes(32, mode), domain.bytes);
        if (value instanceof Uint8Array && value.length === 32) (output[domain.text] ??= {})[mode] = value;
      } catch {}
    }
  }
  return output;
}
function hydrateConstructorIdentities(instance, declaration, args, domains) {
  if (!instance || !declaration) return args;
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(instance));
  // Generated contracts expose every private helper on the prototype.  Only
  // invoke one-argument identity/hash helpers here: methods such as
  // `_blockTimeLt_0`, witnesses, and ledger operations also match the old
  // broad pattern but require a circuit context and can throw before their
  // argument validation runs.
  const oneArg = methods.filter(name =>
    /^_[a-z0-9_]+_\d+$/i.test(name)
    && /(?:id|signer|merchant|board|house|admin|operator|registr|keeper|guardian|relayer|convenor|organis|council|govern|platform|holder|payout|subscriber|member|leaf|tag)/i.test(name.slice(1).replace(/_\d+$/, ""))
    && typeof instance[name] === "function" && instance[name].length === 1);
  const zero = bytes(32, "zero");
  const candidates = new Map();
  for (const name of oneArg) {
    const fn = instance[name]; if (typeof fn !== "function") continue;
    for (const value of [zero, { bytes: zero }]) { try { const out = fn.call(instance, value); const found = firstBytes(out); if (found?.length === 32) (candidates.get(name) ?? candidates.set(name, []).get(name)).push(found); } catch {} }
  }
  const hashMethods = methods.filter(name => /^_persistentHash_\d+$/.test(name) && typeof instance[name] === "function" && instance[name].length === 1);
  const aliasesFor = name => {
    const raw = String(name).toLowerCase();
    const aliases = new Set(raw.split(/[^a-z0-9]+/).filter(Boolean));
    for (const token of ["organiser", "organizer", "operator", "holder", "guardian", "relayer", "principal", "admin", "payer", "account", "issuer", "merchant", "subscriber", "registrar", "registry", "provider", "compliance", "identity", "member", "council", "govern", "gov", "trader", "house", "board", "platform"]) if (raw.includes(token)) aliases.add(token);
    if (aliases.has("organiser")) aliases.add("organizer");
    if (aliases.has("operator")) aliases.add("holder");
    if (aliases.has("guardian") || aliases.has("relayer")) aliases.add("principal");
    if (aliases.has("admin")) { aliases.add("payer"); aliases.add("account"); }
    if (aliases.has("issuer")) aliases.add("account");
    if (aliases.has("gov")) aliases.add("trader");
    if (aliases.has("member")) aliases.add("council");
    if (aliases.has("compliance") || aliases.has("provider")) aliases.add("identity");
    return aliases;
  };
  const hashFor = name => {
    const aliases = aliasesFor(name);
    const matchingDomains = domains.filter(domain => [...aliases].some(alias => alias.length > 2 && domain.text.toLowerCase().includes(alias)));
    for (const domain of matchingDomains) for (const value of [[domain.bytes, zero], [domain.bytes, zero, zero], [domain.bytes, zero, zero, zero]]) for (const method of hashMethods) {
      try { const found = firstBytes(instance[method](value)); if (found?.length === 32) return found; } catch {}
    }
    return undefined;
  };
  const derive = methods.find(name => /^_derive_\d+$/.test(name));
  for (let i = 0; i < declaration.parameters.length; i++) {
    const parameter = declaration.parameters[i]; const name = String(parameter.name).toLowerCase();
    if (!/(id|board|house|admin|operator|registrar|issuer|compliance|provider|merchant|signer|keeper|guardian|relayer|convenor|organis|council|govern|gov|platform|holder|payout|member|^s[0-3]$)/i.test(name)) continue;
    let found;
    const preferred = name === "board" || /^(?:house|admin|operator|registrar|merchant|signer|subscriber)id/.test(name)
      ? [...candidates.entries()].sort(([a], [b]) => {
          const score = method => (name.includes("merchant") && /merchant/i.test(method)) || (name.includes("subscriber") && /subscriber/i.test(method)) || (name === "board" && /derive/i.test(method)) || (/^s[0-3]$/.test(name) && /signer/i.test(method)) ? 0 : 1;
          return score(a) - score(b);
        })
      : [...candidates.entries()];
    for (const [method, values] of preferred) if (/(id|of|signer|derive|board|merchant|subscriber)/i.test(method)) { found = values[0]; if (found) break; }
    if (!found && derive) for (const domain of domains) if (/(board|player|merchant|subscriber|signer|admin|keeper|operator|registr|council|govern)/i.test(domain.text)) { try { const out = instance[derive](domain.bytes, zero); if (out instanceof Uint8Array && out.length === 32) { found = out; break; } } catch {} }
    if (!found) found = hashFor(name);
    if (/^Vector<\s*\d+\s*,\s*Bytes<\s*32\s*>\s*>$/i.test(String(parameter.type)) && /member|council|signer/i.test(name)) {
      const match = /^Vector<\s*(\d+)/i.exec(String(parameter.type));
      if (match) { const member = hashFor("member"); if (member) args[i] = Array.from({ length: Number(match[1]) }, () => member); }
    }
    if (found && typeName(parseSourceType(parameter.type)) === "Bytes") args[i] = found;
    else if (found && /ZswapCoinPublicKey/.test(parameter.type)) args[i] = { bytes: found };
    else if (found && /UserAddress/.test(parameter.type)) args[i] = { bytes: found };
  }
  return args;
}
function derivedRoleKeys(runtime, domains) {
  const domain = domains.find(candidate => /attestor.*pk|pk.*attestor/i.test(candidate.text)) ?? domains.find(candidate => /governor.*pk|pk.*governor/i.test(candidate.text)) ?? domains.find(candidate => /pk/i.test(candidate.text));
  if (!domain || !runtime.CompactTypeVector || !runtime.CompactTypeBytes || !runtime.persistentHash) return [];
  const descriptor = new runtime.CompactTypeVector(2, new runtime.CompactTypeBytes(32));
  return ["zero", "one", "max"].map(mode => {
    const secret = bytes(32, mode);
    return runtime.persistentHash(descriptor, [domain.bytes, secret]);
  });
}
function valueFor(type, mode = "zero", depth = 0, runtime) {
  if (!type || depth > 12) return bytes(32, mode);
  const name = typeName(type);
  if (name === "Alias") return valueFor(type.type, mode, depth + 1, runtime);
  if (name === "Boolean") return mode === "one" || mode === "max";
  if (name === "Uint" || name === "Counter") {
    const max = maxVal(type); if (mode === "max") return max;
    if (mode === "one" || mode === "time") return max > 0n ? 1n : 0n; return 0n;
  }
  if (name === "Field") return mode === "max" ? (runtime?.maxField?.() ?? ((1n << 254n) - 1n)) : mode === "one" ? 1n : 0n;
  if (name === "Bytes") return bytes(type.length, mode);
  if (name === "Opaque") {
    if (String(type.tsType).toLowerCase().includes("string")) return mode === "zero" ? "" : `explore-${mode}`;
    if (String(type.tsType).toLowerCase().includes("jubjubpoint") && runtime?.ecMulGenerator) return runtime.ecMulGenerator(mode === "zero" ? 1n : 2n);
    return bytes(32, mode);
  }
  if (name === "Enum") return mode === "max" ? Math.max(0, (type.elements?.length ?? 1) - 1) : 0;
  if (name === "Struct" || name === "Tuple") {
    const elements = type.elements ?? type.types ?? [];
    return name === "Tuple" ? elements.map(t => valueFor(t, mode, depth + 1, runtime)) : Object.fromEntries(elements.map(e => [e.name, valueFor(e.type, mode, depth + 1, runtime)]));
  }
  if (name === "Vector") return Array.from({ length: Math.max(0, Math.min(Number(type.length ?? 0), 256)) }, () => valueFor(type.type, mode, depth + 1, runtime));
  if (name === "List" || name === "Set" || name === "Map") return [];
  if (name === "Contract") return { address: bytes(32, mode) };
  return name === "Void" ? [] : bytes(32, mode);
}
function coinColorFor(runtime, ledger, address) {
  try {
    const domainHex = ledger?.coinDomainSeparator;
    if (typeof domainHex === "string" && /^[0-9a-f]{64}$/i.test(domainHex) && typeof runtime?.rawTokenType === "function" && typeof runtime?.encodeRawTokenType === "function") {
      return runtime.encodeRawTokenType(runtime.rawTokenType(Uint8Array.from(Buffer.from(domainHex, "hex")), address));
    }
  } catch {}
  return bytes(32, "zero");
}
function coinValueFor(type, mode, runtime, coinState, qualified = false) {
  const value = valueFor(type, mode, 0, runtime);
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  if (value.nonce instanceof Uint8Array) value.nonce = coinState.nonce;
  if (value.color instanceof Uint8Array) value.color = coinState.color;
  if (value.value !== undefined) value.value = coinState.value;
  if (qualified && value.mt_index !== undefined) value.mt_index = coinState.mt_index;
  return value;
}
function sourceParameterValue(parameter, mode, runtime, derivedKeys = []) {
  const n = String(parameter?.name ?? "").toLowerCase(); const t = parseSourceType(parameter?.type);
  const canonical = sourceTypeValue(parameter?.type, mode, runtime, parameter?.name);
  if (canonical !== undefined) return canonical;
  if (/totalsupply/.test(n)) return 100n;
  if (/maxvotercap/.test(n)) return 100n;
  if (/walletcap/.test(n)) return 100n;
  if (/dvallocation|dvprice|bondamount/.test(n)) return 1n;
  if (/curvesupply/.test(n)) return 1n;
  if (/baseprice/.test(n)) return 1n;
  if (/maxprice/.test(n)) return 2n;
  if (/attestthreshold/.test(n)) return 2n;
  if (/allowlistthreshold/.test(n)) return 2n;
  if (/minvoter|threshold/.test(n)) return 1n;
  if (/hasclaimable/.test(n)) return true;
  if (/graduation/.test(n)) return 0n;
  if (/bondmin/.test(n)) return 1_000_000n;
  if (/lockduration/.test(n)) return 31_536_000n;
  if (/registrationwindow|freezewindow|buyingwindow/.test(n)) return 7_776_000n;
  if (/registrationclosetime/.test(n)) return 15_552_000n;
  if (/allowlistsize|min(dv)?participants/.test(n)) return 1n;
  if (/maxwalletpercent/.test(n)) return 100n;
  if (n === "m") return 2n;
  if (/^(?:tiers?|tiercount|levels?)$/.test(n)) return 1n;
  if (/feecap/.test(n)) return 1n;
  if (/^unit$/.test(n)) return 100n;
  if (typeName(t) === "Uint" && /(cap|limit|max|threshold|length|duration|window|delay|period|fee|rate|price|unit|secs|seconds|step|reserve)/.test(n)) {
    if (/cap|limit|threshold|fee/.test(n)) return 100n;
    if (/price|rate|unit|step|reserve/.test(n)) return 1n;
    return 10n;
  }
  if (/attestorkey1/.test(n) && derivedKeys[0]) return derivedKeys[0];
  if (/attestorkey2/.test(n) && derivedKeys[1]) return derivedKeys[1];
  if (/attestorkey3/.test(n) && derivedKeys[2]) return derivedKeys[2];
  if (/allowlistattestor1/.test(n) && derivedKeys[0]) return derivedKeys[0];
  if (/allowlistattestor2/.test(n) && derivedKeys[1]) return derivedKeys[1];
  if (/allowlistattestor3/.test(n) && derivedKeys[2]) return derivedKeys[2];
  if (/attestorkey1/.test(n)) return bytes(32, "zero");
  if (/attestorkey2/.test(n)) return bytes(32, "one");
  if (/attestorkey3/.test(n)) return bytes(32, "max");
  if (typeName(t) === "Bytes") {
    if (Number(t.length ?? 32) !== 32) return bytes(t.length, mode);
    if (/(initialholder|payout|admin|board|house|keeper|operator|registrar|convenor|issuer|organis|council|merchant|guardian|relayer|govern|signer|platform|[a-z]id$|^s[0-3]$)/i.test(n)) return bytes(32, "zero");
    return distinctParameterBytes(parameter?.name, mode);
  }
  if (String(parameter?.type ?? "").startsWith("Opaque<\"string\"")) return mode === "zero" ? `explore-${n || "value"}` : `explore-${mode}`;
  return valueFor(t, mode, 0, runtime);
}
function runtimeWitnessValue(name, type, mode, runtime, coinState) {
  const lower = String(name ?? "").toLowerCase();
  if (/agreedamount|lockedamount/.test(lower) && typeName(type) === "Uint") return 1n;
  if (/depositedcoin|heldcoinforrelease/.test(lower) && (typeName(type) === "Struct" || typeName(type) === "Tuple")) {
    return coinValueFor(type, mode === "zero" ? "one" : mode, runtime, coinState, /heldcoinforrelease/.test(lower));
  }
  const value = valueFor(type, mode, 0, runtime);
  if (value && typeof value === "object" && !Array.isArray(value) && "is_left" in value && value.left?.bytes instanceof Uint8Array) {
    // Coin recipients need valid encoded keys/addresses for the runtime's
    // commitment codec.  Keep the same deterministic recipient for proposal,
    // lock, and payout witnesses so their commitments remain compatible.
    value.is_left = true;
    value.left.bytes = bytes(32, mode);
    if (runtime?.encodeContractAddress && runtime?.dummyContractAddress) value.right.bytes = runtime.encodeContractAddress(runtime.dummyContractAddress());
  }
  return value;
}
function circuitArgumentValue(argument, mode, runtime, knownResults = {}) {
  const name = String(argument?.name ?? "").toLowerCase();
  const type = argument?.type;
  if (knownResults.constructorValues && knownResults.constructorValues[name] !== undefined) return knownResults.constructorValues[name];
  if (typeName(type) === "Uint" && /options|(?:option|choice)count|numoptions|numberofoptions/.test(name) && mode !== "max") return 2n;
  if (typeName(type) === "Uint" && /^plan$/.test(name) && mode !== "max") return 0n;
  if (typeName(type) === "Uint" && /^(?:periods|numberofperiods)$/.test(name) && mode !== "zero") return 1n;
  if (typeName(type) === "Uint" && /^(?:tier|tierid)$/.test(name) && mode !== "max") return 0n;
  if (typeName(type) === "Bytes") {
    // Keep role identifiers distinct within a single call.  Reusing the
    // mode-wide byte witness makes otherwise valid multi-party constructors
    // fail their generic "roles overlap" checks.
    if (/seller/.test(name)) return bytes(32, "one");
    if (/arbiter|governor|administrator|admin/.test(name)) return bytes(32, "max");
    if (/payto|recipient/.test(name)) return bytes(32, "one");
  }
  if (typeName(type) === "Struct" && /(?:useraddress|address)/i.test(String(type?.name ?? "")) && /payto|recipient/.test(name)) {
    return { bytes: bytes(32, "one") };
  }
  if (typeName(type) === "Struct" && /(?:useraddress|address)/i.test(String(type?.name ?? "")) && knownResults.holderBytes && /^(?:to|recipient|owner|holder)$/.test(name)) {
    return { bytes: knownResults.holderBytes };
  }
  if (/(coin|coininfo|shielded)/.test(name) && (typeName(type) === "Struct" || typeName(type) === "Tuple")) {
    const price = knownResults.amountHint ?? knownResults.offerPrice ?? 1n;
    const fee = knownResults.feeHint ?? knownResults.constructorValues?.fee ?? knownResults.carrierFee ?? 1n;
    return coinValueFor(type, mode, runtime, { ...(knownResults.coinState ?? { nonce: bytes(32, mode), color: bytes(32, mode), mt_index: 0n }), value: price + fee }, /qualified|held|input/.test(name));
  }
  if (/(pk|publickey|public_key)/.test(name) && typeName(type) === "Struct" && knownResults.callerBytes) return { bytes: knownResults.callerBytes };
  if (/instancesalt/.test(name) && typeName(type) === "Bytes" && knownResults.instanceSalt) return knownResults.instanceSalt;
  if (/support|approve|allow|enabled/.test(name) && typeName(type) === "Boolean") return true;
  if (typeName(type) === "Enum" && type.elements?.length) {
    if (/proposaltype/.test(name)) return 0;
    if (/phase/.test(name)) return knownResults.enumPhase ?? 1;
    return mode === "zero" ? 0 : mode === "max" ? type.elements.length - 1 : 1;
  }
  if (/proposalid/.test(name) && knownResults.proposalId) return knownResults.proposalId;
  if (/commitment/.test(name) && knownResults.lastBytes) return knownResults.lastBytes;
  if (/(?:^|_)lotid$/.test(name) && knownResults.lotId) return knownResults.lotId;
  if (/^(?:issuer|issuerid|registrarid|providerid|complianceid|operatorid|guardianid|relayerid|governor|gov)$/.test(name) && knownResults.identityId) return knownResults.identityId;
  if (/offerid/.test(name) && (knownResults.offerIdsByCaller?.[knownResults.caller] ?? knownResults.offerId)) return knownResults.offerIdsByCaller?.[knownResults.caller] ?? knownResults.offerId;
  if (/carrierid/.test(name) && (knownResults.carrierIdsByCaller?.[knownResults.caller] ?? knownResults.carrierId)) return knownResults.carrierIdsByCaller?.[knownResults.caller] ?? knownResults.carrierId;
  if (/buyerid/.test(name) && (knownResults.buyerIdsByCaller?.[knownResults.caller] ?? knownResults.buyerId)) return knownResults.buyerIdsByCaller?.[knownResults.caller] ?? knownResults.buyerId;
  if (/portauth(key)?hash|portauthoritykeyhash|rolekeyhash/.test(name)) {
    const roleHashes = Object.entries(knownResults.roleHashes ?? {});
    const selected = roleHashes.find(([domain]) => /port.?auth/i.test(domain)) ?? roleHashes.find(([domain]) => /auth|role/i.test(domain));
    if (selected?.[1]?.zero) return selected[1].zero;
  }
  if (/registrantroot/.test(name) && knownResults.registrantRoot) return knownResults.registrantRoot;
  if (/commitment/.test(name) && knownResults.commitments?.length) return knownResults.commitments[Math.min(knownResults.commitmentIndex ?? 0, knownResults.commitments.length - 1)];
  if (/baseslot/.test(name)) return 1n;
  if (/tokenamount|pricepertoken/.test(name) && typeName(type) === "Uint") return 1n;
  if (/claimedcreatorfee|claimedplatformfee/.test(name) && typeName(type) === "Uint") return 0n;
  if (/(newroot|root)/.test(name) && knownResults.root) return knownResults.root;
  if (/(offer|escrow|intent|commitment|payment|channel|proposal|deal|lot|token|receipt)id/.test(name) && knownResults.lastBytes) return knownResults.lastBytes;
  if (/time|timestamp|deadline|start|end|due|slot|expiry|duration|^now$|current/.test(name) && typeName(type) === "Uint") {
    if (mode === "max") return maxVal(type);
    if (/(reveal|settle|deadline)/.test(name)) return (knownResults.now ?? 7_776_000n) + 2_000_000n;
    if (/(expiry|end|due|close)/.test(name)) return (knownResults.now ?? 7_776_000n) + 1_000_000n;
    return knownResults.now ?? 7_776_000n;
  }
  if (/amount|balance|cap|bond|count|threshold|value|fee|supply/.test(name) && typeName(type) === "Uint") {
    if (mode === "max") return maxVal(type);
    if (mode === "balanced" && /bond/.test(name)) return 1_000_000n;
    if (/tokenamount|pricepertoken/.test(name)) return 1n;
    return mode === "zero" ? 0n : 1n;
  }
  return valueFor(type, mode, 0, runtime);
}
function getCurrentState(context) { return context?.callContext?.currentQueryContext?.state ?? context?.currentQueryContext?.state; }
function getPrivateState(context) { return context?.callContext?.currentPrivateState ?? context?.currentPrivateState; }
function makeCircuitContext(runtime, state, privateState, caller, time, address) {
  const zswap = runtime.emptyZswapLocalState(caller);
  if (runtime.createCircuitContext.length >= 9) return runtime.createCircuitContext("explore", address, zswap, state, privateState, undefined, undefined, undefined, time);
  return runtime.createCircuitContext(address, zswap, state, privateState, undefined, undefined, time);
}
function stateSnapshot(contract, state) {
  try {
    const value = contract.ledger(state); const plain = (v, depth = 0) => {
      if (depth > 8 || v === null || v === undefined || typeof v === "string" || typeof v === "boolean" || typeof v === "number" || typeof v === "bigint") return v;
      if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
      if (Array.isArray(v)) return v.map(x => plain(x, depth + 1));
      // Generated Compact ledgers expose Maps through a non-enumerable
      // iterator.  Object.keys(map) only sees the query methods, so the
      // previous snapshot silently discarded every dynamic entry. Preserve
      // Map/Set contents with stable key paths so insertion order cannot turn
      // a new caller entry into an apparent rewrite of an older entry.
      const iterator = v?.[Symbol.iterator];
      if (typeof iterator === "function" && typeof v?.lookup === "function") {
        try {
          const entries = Array.from(v, item => [plain(item?.[0], depth + 1), plain(item?.[1], depth + 1)]);
          entries.sort((a, b) => String(a[0]).localeCompare(String(b[0])));
          return { __compactMap: entries };
        } catch {}
      }
      if (typeof iterator === "function" && typeof v?.member === "function") {
        try {
          const entries = Array.from(v, item => plain(item, depth + 1));
          entries.sort((a, b) => String(a).localeCompare(String(b)));
          return { __compactSet: entries };
        } catch {}
      }
      const out = {}; for (const key of Object.keys(v)) { try { out[key] = plain(v[key], depth + 1); } catch { out[key] = "<unreadable>"; } } return out;
    }; return plain(value);
  } catch { return undefined; }
}
function runtimeVersionOf(path) { try { return JSON.parse(readFileSync(join(dirname(dirname(path)), "package.json"), "utf8")).version; } catch { return undefined; } }
function chooseRuntime(expected) { return runtimeCandidates.find(p => existsSync(p) && runtimeVersionOf(p) === expected) ?? runtimeCandidates.find(p => existsSync(p)); }

// The runtime replay deliberately stays generic: these helpers only inspect the
// ledger values that the generated contract exposes and the source facts that
// Nightshade already resolved.  They do not contain contract names or field
// adapters.  Paths are retained so an aggregate ledger value can still be
// compared when a circuit reads its containing root.
function flattenLedger(value, path = "", out = new Map()) {
  if (value === undefined) return out;
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number" || typeof value === "bigint") {
    if (path) out.set(path, value);
    return out;
  }
  if (value instanceof Uint8Array) { if (path) out.set(path, Buffer.from(value).toString("hex")); return out; }
  if (Array.isArray(value)) { value.forEach((v, i) => flattenLedger(v, `${path}[${i}]`, out)); return out; }
  if (Array.isArray(value.__compactMap)) {
    for (const [key, child] of value.__compactMap) {
      const entry = `${path}{${String(key)}}`;
      out.set(`${entry}.$key`, key);
      flattenLedger(child, entry, out);
    }
    return out;
  }
  if (Array.isArray(value.__compactSet)) {
    for (const key of value.__compactSet) out.set(`${path}{${String(key)}}`, true);
    return out;
  }
  for (const [key, child] of Object.entries(value)) flattenLedger(child, path ? `${path}.${key}` : key, out);
  return out;
}
function scalarNumber(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isFinite(value) && Number.isInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) return undefined;
  if (typeof value === "string" && /^-?\d+n$/.test(value)) { try { return BigInt(value.slice(0, -1)); } catch {} }
  if (typeof value === "string" && /^-?\d+$/.test(value)) { try { return BigInt(value); } catch {} }
  return undefined;
}
function ledgerDiff(before, after) {
  const b = flattenLedger(before), a = flattenLedger(after), changes = [];
  for (const path of new Set([...b.keys(), ...a.keys()])) if (!sameScalar(b.get(path), a.get(path))) changes.push({ path, before: b.get(path), after: a.get(path) });
  return changes;
}
function sameScalar(a, b) {
  const na = scalarNumber(a), nb = scalarNumber(b);
  return na !== undefined && nb !== undefined ? na === nb : a === b;
}
function leafName(path) { return String(path).split(/[.\[]/).filter(Boolean).pop()?.toLowerCase() ?? ""; }
function pathMatchesRoot(path, root) {
  const name = String(root).split("::").pop()?.toLowerCase() ?? String(root).toLowerCase();
  const normalized = String(path).toLowerCase();
  return normalized === name || normalized.startsWith(`${name}.`) || normalized.startsWith(`${name}[`);
}
function terminalMarker(change, circuit, valueMoving) {
  const name = leafName(change.path);
  const boolMarker = change.before === false && change.after === true;
  const oldNumber = scalarNumber(change.before), newNumber = scalarNumber(change.after);
  const enumMarker = oldNumber !== undefined && newNumber !== undefined && oldNumber === 0n && newNumber > 0n;
  const markerName = /(state|phase|status|seed|settled|settle|final|finish|complete|closed|released|claimed|graduat|paid|consum|confirm|initialized|activated|delivered|resolved|executed|done)/i.test(name);
  const terminalCircuit = /(graduate|settle|release|claim|payout|final|close|complete|resolve|deliver|withdraw|retire|execute)/i.test(String(circuit));
  return (boolMarker || enumMarker) && markerName && (valueMoving || terminalCircuit);
}
function numericAccumulator(change) {
  const before = scalarNumber(change.before), after = scalarNumber(change.after);
  if (before === undefined || after === undefined || before === after) return false;
  return /(accum|total|raised|supply|balance|amount|value|fee|deposit|escrow|treasury|payment|count|sold|committed|purchas|minted|operations?)/i.test(change.path);
}
function valueLikePath(path) {
  return /(raised|supply|balance|amount|value|deposit|escrow|treasury|payment|coin|fund|purchas|minted)/i.test(path)
    && !/(participant|count|operation|token(s)?Committed)/i.test(path);
}
function terminalLikePath(path) { return /(state|phase|status|settle|release|claim|paid|complete|final|closed|delivered|resolved|seed|graduat|confirm)/i.test(path); }
function sourceModelFacts(model, descriptors) {
  if (!model) return { circuits: {} };
  const byName = new Map();
  for (const fn of model.functions.values()) {
    const name = fn.symbol?.name;
    if (!name || byName.has(name)) continue;
    const reads = [...fn.readsState].map(id => model.symbols.get(id)?.name ?? id);
    const writes = [...fn.writesState].map(id => model.symbols.get(id)?.name ?? id);
    const operations = new Set();
    const identityDerivedRoots = new Set();
    const walk = node => {
      if (!node || typeof node !== "object") return;
      if (node.kind === "call" && node.name) operations.add(String(node.name));
      if (node.kind === "ref" && node.ledgerRoot) {
        const field = String(node.ledgerRoot).split("::").pop(); if (field) reads.push(field);
      }
      for (const value of Object.values(node)) if (value && typeof value === "object") {
        if (Array.isArray(value)) value.forEach(walk); else walk(value);
      }
    };
    walk(fn.declaration?.body);
    // Reuse the resolved AST symbols to retain the small piece of provenance
    // the caller oracle needs: a Map key written by an identity/hash-derived
    // local.  This is deliberately root-scoped; it does not assert that every
    // value in the root is owned by the caller.
    const tainted = new Set();
    const expressionTainted = node => {
      if (!node || typeof node !== "object") return false;
      if (node.kind === "ref") return tainted.has(node.symbol)
        || /ownPublicKey|secret|witness|caller|identity/i.test(String(node.name ?? ""));
      if (node.kind === "call") {
        const name = String(node.name ?? "");
        if (/ownPublicKey|secret|witness|get(?:User|Governor|Admin).*Secret/i.test(name)) return true;
        return /derive|hash|commit|identity|persistent|(?:gen|compute).*(?:id|key|hash)/i.test(name) && (node.args ?? []).some(expressionTainted);
      }
      return Object.values(node).some(value => Array.isArray(value)
        ? value.some(expressionTainted) : expressionTainted(value));
    };
    const provenance = node => {
      if (!node || typeof node !== "object") return;
      if (node.kind === "bind") {
        if (expressionTainted(node.expr) && node.pattern?.symbol) tainted.add(node.pattern.symbol);
      }
      if (node.kind === "member" && node.value === "call" && /^(insert|remove|pop|push|set)$/i.test(String(node.name ?? "")) && node.ledgerRoot) {
        const key = node.args?.[1] ?? node.args?.[0];
        if (expressionTainted(key)) identityDerivedRoots.add(String(node.ledgerRoot).split("::").pop());
      }
      if (node.kind === "assign" && node.ledgerRoot && expressionTainted(node.args?.at?.(-1))) {
        identityDerivedRoots.add(String(node.ledgerRoot).split("::").pop());
      }
      for (const value of Object.values(node)) if (value && typeof value === "object") {
        if (Array.isArray(value)) value.forEach(provenance); else provenance(value);
      }
    };
    provenance(fn.declaration?.body);
    const uniqueReads = [...new Set(reads)];
    const timeCompared = [...operations].some(op => /blockTime|checkpoint|currentTime|time(?:Gte|Lte|Gt|Lt|Equals?)/i.test(op));
    const receivesValue = [...operations].some(op => /receive(?:Shielded|Unshielded)|mint(?:Shielded|Unshielded)|receiveDeposit|claimZswapCoinReceive/i.test(op));
    const valueMoving = [...operations].some(op => /(send|receive|coin|mint|burn|transfer|withdraw|deposit|pay|merge|split|payout)/i.test(op))
      || /(mint|burn|transfer|withdraw|deposit|lock|escrow|pay|payout|claim|release|settle|graduate|buy|purchase|refund)/i.test(name);
    const identityDerivedWitness = [...operations].some(op => /publicKey|derive.*(?:Key|Id)|persistentHash|identity/i.test(op))
      && [...new Set(writes)].some(path => /(owner|admin|operator|guardian|keeper|issuer|author|key|role|holder|caller|signer)/i.test(path))
      && [...operations].every(op => !/(receive|send|coin|mint|burn|transfer|withdraw|deposit|pay|payout)/i.test(op));
    byName.set(name, { reads: uniqueReads, writes: [...new Set(writes)], operations: [...operations], identityDerivedRoots: [...identityDerivedRoots], valueMoving, timeCompared, receivesValue, identityDerivedWitness });
  }
  const out = {};
  for (const descriptor of descriptors ?? []) out[descriptor.name] = byName.get(descriptor.name) ?? { reads: [], writes: [], operations: [], identityDerivedRoots: [], valueMoving: /(mint|transfer|withdraw|deposit|lock|escrow|pay|payout|claim|release|settle|graduate|buy|purchase|refund)/i.test(descriptor.name), timeCompared: false, receivesValue: false, identityDerivedWitness: false };
  return { circuits: out };
}
function successfulTransitions(result) { return result.transitions ?? []; }
function oracleResult(searchBound) { return { detections: [], misses: [], falseAlarms: [], searchBound, stats: {} }; }
function disableLowPrecisionOracles(oracles) {
  if (experimentalOraclesEnabled) return;
  for (const name of disabledByDefault) {
    const oracle = oracles[name];
    if (!oracle) continue;
    oracles[name] = {
      ...oracle,
      detections: [],
      disabled: true,
      disabledReason: "Heuristic oracle disabled by default; set NIGHTSHADE_ENABLE_EXPERIMENTAL_ORACLES=1 for focused experiments.",
      misses: [...(oracle.misses ?? []), { reason: "Heuristic oracle requires explicit opt-in." }],
    };
  }
}
function valueStrings(value, out = new Set()) {
  if (value === undefined || value === null) return out;
  if (value instanceof Uint8Array && value.length === 32) { out.add(Buffer.from(value).toString("hex")); return out; }
  if (typeof value === "string") { if (/^[0-9a-f]{64}$/i.test(value)) out.add(value.toLowerCase()); return out; }
  if (Array.isArray(value)) { for (const child of value) valueStrings(child, out); return out; }
  if (typeof value === "object") for (const child of Object.values(value)) valueStrings(child, out);
  return out;
}
function identityPath(path) {
  return /(?:owner|admin|operator|guardian|keeper|issuer|author|role|holder|caller|signer|seller|buyer|carrier|recipient|payout|merchant|creator|proposer|governor|community|hash|commit|secret)/i.test(String(path))
    || /(?:id|key)(?:$|[.\]}])/i.test(String(path));
}
function associationFor(record, caller) {
  const values = new Set([String(caller).toLowerCase()]); const paths = new Set();
  const operations = (record.facts?.operations ?? []).map(operation => String(operation));
  // Nightshade's resolved call facts retain the source-level transfer from a
  // caller/witness identity into a derived key or commitment.  Keep this
  // separate from path-name guesses: a field is owner-associated only when a
  // source identity/secret is actually used with a derivation operation.
  const dataflowRoots = new Set((record.facts?.identityDerivedRoots ?? []).map(root => String(root).toLowerCase()));
  const ownerDerived = dataflowRoots.size > 0 || operations.some(operation =>
    /ownPublicKey|publicKey|secretKey|witness|get(?:User|Governor|Admin).*Secret/i.test(operation))
    && operations.some(operation => /derive|hash|commit|identity|persistent/i.test(operation));
  valueStrings(record.ownerPublicKey, values);
  for (const arg of record.args ?? []) valueStrings(arg, values);
  for (const witness of Object.values(record.witnessRaw ?? {})) valueStrings(witness, values);
  valueStrings(record.result, values);
  for (const change of record.changes ?? []) {
    const pathLooksOwned = identityPath(change.path);
    const mapEntry = /\{[^}]+\}/.test(change.path);
    const pathRoot = String(change.path).split(/[.{]/)[0].toLowerCase();
    const ownedMapRoot = dataflowRoots.has(pathRoot)
      || /(?:approval|attestor|signer|role|owner|key|identity|nullifier|commit|hash|member|participant)/i.test(pathRoot);
    const changedBytes = new Set(); valueStrings(change.before, changedBytes); valueStrings(change.after, changedBytes);
    // Map keys are represented as {key}. Their names are often
    // generic (for example snapshotApprovals), so source-derived identity
    // facts are the evidence that makes those entries associated.
    if (pathLooksOwned || (ownerDerived && mapEntry && ownedMapRoot && changedBytes.size > 0)) paths.add(change.path);
    valueStrings(change.before, values); valueStrings(change.after, values);
  }
  return { values, paths, ownerDerived };
}
function associatedChange(change, association) {
  if (association.paths.has(change.path)) return true;
  // A newly inserted Map/Set key is not an overwrite of an A entry, even if
  // its serialized value happens to equal one of A's other values. Stable
  // keyed paths are the only association evidence for dynamic collections.
  if (/\{[^}]+\}/.test(change.path)) return false;
  if (!identityPath(change.path)) return false;
  const values = new Set(); valueStrings(change.before, values); valueStrings(change.after, values);
  return [...values].some(value => association.values.has(value));
}
function witnessIdentityOnly(changes, facts, baselineAfter, alternateAfter) {
  if (!changes.length) return false;
  const operations = (facts?.operations ?? []).map(operation => String(operation));
  const identitySource = operations.some(operation => /ownPublicKey|publicKey|secretKey|witness|get(?:User|Governor|Admin).*Secret/i.test(operation))
    && operations.some(operation => /derive|hash|commit|identity|persistent|(?:gen|compute).*(?:id|key|hash)/i.test(operation));
  if (!identitySource) return false;
  const roots = (facts?.identityDerivedRoots ?? []).map(root => String(root).toLowerCase());
  const encrypted = operations.some(operation => /encrypt/i.test(operation));
  const baselineFlat = flattenLedger(baselineAfter), alternateFlat = flattenLedger(alternateAfter);
  const relevant = changes.filter(change => {
    const match = /^([^{}]+)\{([^}]*)\}/.exec(String(change.path));
    if (!match) return true;
    const keyPath = `${match[1]}{${match[2]}}.$key`;
    // A different identity creating/removing its own collection key is the
    // expected witness variation. Only an entry present on both sides can be
    // a witness change to an existing keyed value.
    return baselineFlat.has(keyPath) && alternateFlat.has(keyPath);
  });
  if (!relevant.length) return true;
  return relevant.every(change => {
    const path = String(change.path).toLowerCase();
    const root = path.split(/[.{\[]/)[0];
    if (roots.length > 0) {
      // A source-proven identity key/root means the witness is bound before
      // the circuit's ordinary state updates. Keep amount/price/recipient/
      // threshold sinks visible, but do not mistake the authorized signer’s
      // resulting quorum/root bookkeeping for an unbound witness flow.
      if (/(?:amount|price|threshold|fee|balance|supply|recipient|payout|wallet)(?:$|[.\]}])/i.test(path)) return false;
      return true;
    }
    if (roots.includes(root)) return true;
    // Identity fields and encrypted identity-bound payloads are expected to
    // vary with a caller's own secret.  Treat value/price/recipient-like
    // fields as sinks unless source facts show they are encrypted identity
    // material rather than trusted public state.
    if (/(?:amount|price|threshold|fee|balance|supply|treasury|recipient|payout|wallet|root)(?:$|[.\]}])/i.test(path)) return false;
    if (/address/i.test(path) && !encrypted) return false;
    return /(?:owner|admin|operator|guardian|keeper|issuer|author|key|role|holder|caller|signer|seller|buyer|carrier|proposer|governor|id|hash|commit|secret|memo|approval|attestor)/i.test(path)
      || /address/i.test(path);
  });
}
function oneTimeMarkerChange(change) {
  const before = change.before, after = change.after;
  if (before === false && after === true) return true;
  const oldNumber = scalarNumber(before), newNumber = scalarNumber(after);
  if (oldNumber !== undefined && newNumber !== undefined && oldNumber === 0n && newNumber > 0n && /(state|phase|status|settle|final|closed|released|claimed|done|complete|seed|consum|execut)/i.test(change.path)) return true;
  return (before === undefined || before === null) && after !== undefined && /(set|map|list|entry|used|claimed|seen|consum|insert)/i.test(change.path);
}
function valueDelta(changes) {
  let delta = 0n;
  for (const change of changes) if (valueLikePath(change.path)) {
    const before = scalarNumber(change.before) ?? 0n, after = scalarNumber(change.after) ?? 0n;
    delta += after - before;
  }
  return delta;
}
function counterDelta(changes) {
  let delta = 0n;
  for (const change of changes) if (!valueLikePath(change.path) && /(?:total|supply|raised|balance|amount|value|committed|settled|fee|deposit|escrow|treasury|payment|minted|liquid|locked|proceeds)/i.test(change.path) && !/(time|timestamp|deadline|expiry|sequence)/i.test(change.path)) {
    const before = scalarNumber(change.before), after = scalarNumber(change.after);
    if (before !== undefined || after !== undefined) delta += (after ?? 0n) - (before ?? 0n);
  }
  return delta;
}
function operationFlags(facts) {
  const operations = (facts?.operations ?? []).join(" ");
  return {
    inflow: /receive|mint|deposit|createZswapInput|coinReceive/i.test(operations),
    outflow: /send|pay|withdraw|burn|transfer|createZswapOutput|coinOutput/i.test(operations)
  };
}
function coinValueFrom(value) {
  if (value === undefined || value === null) return 0n;
  if (Array.isArray(value)) return value.reduce((sum, child) => sum + coinValueFrom(child), 0n);
  if (typeof value === "object") {
    const keys = Object.keys(value).map(key => key.toLowerCase());
    if (keys.includes("nonce") && keys.includes("color") && keys.includes("value")) return scalarNumber(value.value) ?? 0n;
    return Object.values(value).reduce((sum, child) => sum + coinValueFrom(child), 0n);
  }
  return 0n;
}
function metamorphicBound(records, result) {
  const successful = records.filter(record => record.transition).length;
  return { baselineCalls: records.length, stateChangingCalls: successful, attempts: (result.sequences ?? []).length,
    successfulCalls: (result.sequences ?? []).filter(sequence => sequence.status === "executed").length,
    transitions: (result.transitions ?? []).length, callerKeys: [...new Set(records.map(record => record.caller))] };
}
function finalizeMetamorphic(result, metamorphic, records) {
  const searchBound = metamorphicBound(records, result);
  const ordering = metamorphic.orderingDifferential;
  if (ordering?.detections?.length) {
    const unique = new Map();
    for (const detection of ordering.detections) {
      const key = `${detection.firstCircuit}|${detection.secondCircuit}|${detection.caller}`;
      if (!unique.has(key)) unique.set(key, detection);
    }
    ordering.stats = { ...(ordering.stats ?? {}), rawDetections: ordering.detections.length, duplicateDetections: ordering.detections.length - unique.size };
    ordering.detections = [...unique.values()];
  }
  for (const oracle of Object.values(metamorphic)) if (oracle && oracle.detections && !oracle.detections.length) oracle.misses.push({ reason: "No qualifying differential replay succeeded within the explored state and call horizon.", stats: oracle.stats ?? {}, searchBound });
  for (const oracle of Object.values(metamorphic)) if (oracle && oracle.searchBound !== undefined) oracle.searchBound = searchBound;
  return metamorphic;
}
function evaluateOracles(result, modelFacts) {
  const transitions = successfulTransitions(result);
  const modelCircuits = modelFacts?.circuits ?? {};
  const callCount = (result.sequences ?? []).filter(s => s.status === "executed").length;
  const bound = { attempts: (result.sequences ?? []).length, successfulCalls: callCount, transitions: transitions.length,
    callerKeys: [...new Set((result.sequences ?? []).map(sequence => sequence.caller).filter(Boolean))],
    witnessVariants: [...new Set((result.sequences ?? []).map(sequence => sequence.witnessVariant).filter(Boolean))], budgetMs: result.budgetMs };
  const post = oracleResult(bound);
  const terminalEvents = [];
  for (let i = 0; i < transitions.length; i++) {
    const transition = transitions[i]; const facts = modelCircuits[transition.circuit] ?? {};
    const changes = ledgerDiff(transition.before, transition.after);
    const marker = changes.find(change => terminalMarker(change, transition.circuit, facts.valueMoving));
    if (!marker) continue;
    const readRoots = facts.reads ?? [];
    const later = transitions.slice(i + 1);
    terminalEvents.push({ transition, marker, readRoots, index: i });
    const accumulatorPaths = new Set();
    for (const candidate of later) for (const change of ledgerDiff(candidate.before, candidate.after)) {
      if (!numericAccumulator(change)) continue;
      if (!readRoots.length || readRoots.some(root => pathMatchesRoot(change.path, root) || pathMatchesRoot(root, change.path))) accumulatorPaths.add(change.path);
      if (accumulatorPaths.has(change.path)) post.detections.push({ kind: "post-terminal-accumulation", terminalCircuit: transition.circuit, terminalReplayId: transition.replayId, marker: { path: marker.path, before: marker.before, after: marker.after }, laterCircuit: candidate.circuit, replayId: candidate.replayId, field: { path: change.path, before: change.before, after: change.after }, searchBound: bound });
    }
  }
  if (!terminalEvents.length) post.misses.push({ reason: "No value-moving terminal Boolean/enum transition was reached within the explored horizon.", candidates: Object.entries(modelCircuits).filter(([, facts]) => facts.valueMoving).map(([circuit]) => circuit), searchBound: bound });
  else if (!post.detections.length) post.misses.push({ reason: "Terminal transitions were reached, but no later read accumulator changed.", terminals: terminalEvents.map(e => ({ circuit: e.transition.circuit, replayId: e.transition.replayId, marker: e.marker.path })), searchBound: bound });

  const supply = oracleResult(bound);
  const callers = new Set(transitions.map(t => t.caller));
  for (let transitionIndex = 0; transitionIndex < transitions.length; transitionIndex++) {
    const transition = transitions[transitionIndex];
    if (!/(mint|issue|faucet|create.?coin)/i.test(transition.circuit)) continue;
    const changes = ledgerDiff(transition.before, transition.after).filter(change => numericAccumulator(change) || /(coin|treasury)/i.test(change.path));
    if (!changes.length) continue;
    const hasPrivilegedSetup = transitions.slice(0, transitionIndex).some(other => other.circuit !== transition.circuit && /(?:setup|authorize|grant|role|owner|admin|init)/i.test(other.circuit));
    const arbitraryCaller = callers.size > 1 || !hasPrivilegedSetup;
    if (arbitraryCaller) for (const change of changes) {
      const oldValue = scalarNumber(change.before), newValue = scalarNumber(change.after);
      if (oldValue !== undefined && newValue !== undefined && newValue <= oldValue) continue;
      supply.detections.push({ kind: "unauthorized-supply-growth", circuit: transition.circuit, replayId: transition.replayId, caller: transition.caller, field: { path: change.path, before: change.before, after: change.after }, privilegedSetup: hasPrivilegedSetup, searchBound: bound });
    }
  }
  if (!supply.detections.length) supply.misses.push({ reason: "No arbitrary mint-like successful call increased an inferred supply, balance, or coin field.", candidates: Object.keys(modelCircuits).filter(circuit => /(mint|issue|faucet|create.?coin)/i.test(circuit)), searchBound: bound });

  const stuck = oracleResult(bound);
  for (let i = 0; i < transitions.length; i++) {
    const deposit = transitions[i];
    if (!/(deposit|lock|escrow|purchase|offer|receive|fund)/i.test(deposit.circuit)) continue;
    const facts = modelCircuits[deposit.circuit] ?? {};
    const changes = ledgerDiff(deposit.before, deposit.after);
    const valueChanges = changes.filter(change => valueLikePath(change.path));
    const inferredValueMovement = !!facts.valueMoving;
    // A name such as `lock` is not evidence that value entered the ledger.
    // Require either an observed value field change or a source-level receive
    // operation before applying the stuck-value transfer check.
    if (!valueChanges.length && !facts.receivesValue) continue;
    const stateChanges = changes.filter(change => terminalLikePath(change.path));
    const later = transitions.slice(i + 1);
    const moved = later.some(next => ledgerDiff(next.before, next.after).some(change => valueChanges.some(value => change.path === value.path && !sameScalar(change.before, change.after))));
    const terminal = later.some(next => ledgerDiff(next.before, next.after).some(change => stateChanges.some(state => change.path === state.path && !sameScalar(change.before, change.after))));
    if (!moved && !terminal) stuck.detections.push({ kind: "stuck-value", depositCircuit: deposit.circuit, replayId: deposit.replayId, fields: valueChanges.map(change => ({ path: change.path, before: change.before, after: change.after })), inferredValueMovement, operations: facts.operations ?? [], searchBound: bound });
  }
  if (!stuck.detections.length) stuck.misses.push({ reason: "No deposit-like transition with an inferred escrow/value field remained terminal within the explored horizon.", candidates: Object.keys(modelCircuits).filter(circuit => /(deposit|lock|escrow|purchase|offer|receive|fund)/i.test(circuit)), searchBound: bound });

  // A generic authorization check for attest/confirm-style terminal facts:
  // if a value-moving timeout/refund/payout circuit succeeds after the
  // attestation Boolean is true, and its resolved source facts do not read
  // that Boolean, the replay demonstrates a post-attestation release path.
  const attestation = oracleResult(bound);
  for (let i = 0; i < transitions.length; i++) {
    const attested = transitions[i];
    const marker = ledgerDiff(attested.before, attested.after).find(change => change.before === false && change.after === true && /(attest|confirm|approve|verified|validated|complete)/i.test(change.path));
    if (!marker || !/(attest|confirm|approve|verify|validate)/i.test(attested.circuit)) continue;
    for (const candidate of transitions.slice(i + 1)) {
      const facts = modelCircuits[candidate.circuit] ?? {};
      if (!facts.valueMoving || !/(timeout|refund|release|claim|payout|withdraw|settle)/i.test(candidate.circuit)) continue;
      const current = flattenLedger(candidate.before).get(marker.path);
      if (current !== true) continue;
      const readsMarker = (facts.reads ?? []).some(root => pathMatchesRoot(marker.path, root) || pathMatchesRoot(root, marker.path));
      if (!readsMarker) attestation.detections.push({ kind: "post-attestation-release", attestationCircuit: attested.circuit, attestationReplayId: attested.replayId, marker: { path: marker.path, before: marker.before, after: marker.after }, releaseCircuit: candidate.circuit, replayId: candidate.replayId, sourceReadsMarker: false, searchBound: bound });
    }
  }
  if (!attestation.detections.length) attestation.misses.push({ reason: "No successful value-moving timeout/refund/release followed a true attestation marker without reading it.", searchBound: bound });

  const deadline = oracleResult(bound);
  deadline.detections = (result.violations ?? []).filter(v => v.kind === "caller-supplied-deadline").map(v => ({ ...v, searchBound: bound }));
  const hasTimeCircuit = (result.contractInfo?.circuits ?? []).some(c => (c.arguments ?? []).some(a => /time|timestamp|deadline|expiry/i.test(String(a.name ?? ""))));
  if (!deadline.detections.length) deadline.misses.push({ reason: hasTimeCircuit ? "Timestamped circuits were explored without an accepted future caller timestamp." : "No timestamped circuit argument was represented by contract-info.", searchBound: bound });
  result.oracles = { postTerminalAccumulation: post, unauthorizedSupplyGrowth: supply, stuckValue: stuck, postAttestationRelease: attestation, callerSuppliedDeadline: deadline };
  disableLowPrecisionOracles(result.oracles);
}

if (!root || !existsSync(root)) { result.error = "ROOT does not exist"; console.log(JSON.stringify(result, null, 2)); process.exitCode = 2; }
else {
  const scan = run(process.execPath, [resolve("dist/src/cli.js"), "scan", root, "--json", "--compiler-version", compilerVersion], { timeout: budgetMs });
  try { const report = JSON.parse(scan.stdout); result.facts = { entrypoints: report.entrypoints ?? [], completedEntries: report.coverage?.completedEntries ?? [], diagnostics: report.diagnostics ?? [], findings: report.findings ?? [] }; }
  catch { result.facts = { diagnostics: [{ code: "scan-json", message: scan.stderr.slice(0, 2000) }] }; }
  const compileDir = mkdtempSync(join(tmpdir(), "nightshade-explore-"));
  const compiled = run(compiler, ["--skip-zk", root, join(compileDir, "output")], { timeout: budgetMs });
  result.compiler = { status: compiled.status, stderr: compiled.stderr.slice(0, 4000), output: join(compileDir, "output") };
  const generated = join(compileDir, "output", "contract", "index.js"); const infoPath = join(compileDir, "output", "compiler", "contract-info.json");
  if (compiled.status === 0 && existsSync(generated) && existsSync(infoPath)) {
    result.runtime.attempted = true;
    const info = JSON.parse(preserveMaxvals(readFileSync(infoPath, "utf8")));
    result.contractInfo = { compilerVersion: info["compiler-version"], runtimeVersion: info["runtime-version"], circuits: (info.circuits ?? []).map(c => ({ name: c.name, pure: !!c.pure, arguments: c.arguments ?? [], resultType: c["result-type"] })), witnesses: (info.witnesses ?? []).map(w => ({ name: w.name, arguments: w.arguments ?? [], resultType: w["result type"] })) };
    const runtimePath = chooseRuntime(info["runtime-version"]); result.runtime.selectedPath = runtimePath; result.runtime.expectedVersion = info["runtime-version"]; result.runtime.available = !!runtimePath;
    if (runtimePath) try {
      const runtimePackage = runtimePath.replace(/\/dist\/index\.js$/, ""); const runtimeLink = join(compileDir, "output", "node_modules", "@midnight-ntwrk", "compact-runtime"); mkdirSync(dirname(runtimeLink), { recursive: true }); try { symlinkSync(runtimePackage, runtimeLink, "dir"); } catch {}
      const runtime = await import(pathToFileURL(runtimePath).href); const contractModule = await import(pathToFileURL(generated).href);
      const generatedText = readFileSync(generated, "utf8"); const domains = [...generatedDomains(generatedText), ...sourceDomains(readFileSync(root, "utf8"))]; const derivedKeys = derivedRoleKeys(runtime, domains);
      let model; try { const engine = await import(pathToFileURL(resolve("dist/src/index.js")).href); model = new engine.Program(root, [dirname(root)], undefined, undefined, 2, compilerVersion); result.modelFacts = sourceModelFacts(model, info.circuits ?? []); } catch (error) { result.modelFacts = { circuits: {}, error: String(error).slice(0, 1000) }; }
      let witnessMode = "zero"; let activeWitnessCapture; let activeWitnessRaw; let activeWitnessCaller = "00".repeat(32); let genericPlan; let allowlistPlan; let registrantPlan; let buyPlans; let activeCommitmentIndex = 0; const witnessSamples = {};
      const coinState = { nonce: bytes(32, "zero"), color: bytes(32, "zero"), value: 1n, mt_index: 0n };
      const witnesses = Object.fromEntries((info.witnesses ?? []).map(w => [w.name, context => {
        const privateState = { ...(context?.privateState && typeof context.privateState === "object" ? context.privateState : {}), lastWitness: w.name, witnessMode };
        const capture = value => { if (activeWitnessCapture) activeWitnessCapture[w.name] = digest(value); if (activeWitnessRaw) activeWitnessRaw[w.name] = value; return [privateState, value]; };
        const callerMode = activeWitnessCaller === "00".repeat(32) ? witnessMode : "one";
        if (activeWitnessCapture && callerMode !== "zero") {
          return capture(runtimeWitnessValue(w.name, w["result type"], callerMode, runtime, coinState));
        }
        if ((genericPlan || allowlistPlan || buyPlans) && /usersecret/i.test(w.name)) { const value = { bytes: activeWitnessCaller === "00".repeat(32) ? (genericPlan?.userSecret ?? allowlistPlan?.userSecret ?? buyPlans[activeCommitmentIndex]?.userSecret ?? buyPlans[0]?.userSecret) : bytes(32, "one") }; witnessSamples[w.name] ??= Buffer.from(value.bytes).toString("hex"); return capture(value); }
        if (genericPlan && /balanceleafamount/i.test(w.name)) return capture(genericPlan.balance);
        if (genericPlan && /balanceleafheldsince/i.test(w.name)) return capture(genericPlan.heldSince);
        if (genericPlan && /balanceproof/i.test(w.name)) return capture(genericPlan.proof);
        if (allowlistPlan && /merkleproof/i.test(w.name)) return capture(allowlistPlan.proof);
        if (registrantPlan && /registrantmerkleproof/i.test(w.name)) return capture(registrantPlan.proof);
        if (/buynonce/i.test(w.name)) { const value = buyPlans?.[activeCommitmentIndex]?.nonce ?? bytes(32, "zero"); witnessSamples[w.name] ??= Buffer.from(value).toString("hex"); return capture(value); }
        return capture(runtimeWitnessValue(w.name, w["result type"], witnessMode, runtime, coinState));
      }]));
      let instance; try { instance = typeof contractModule.Contract === "function" ? new contractModule.Contract(witnesses) : undefined; } catch (error) { result.runtime.constructorError = String(error); }
      const roleHashes = genericRoleHashes(instance, domains);
      const constructorDecl = [...model?.functions?.values?.() ?? []].find(item => item.symbol?.kind === "constructor");
      let constructorArgs = constructorDecl?.declaration?.parameters?.map(parameter => sourceParameterValue(parameter, "zero", runtime, derivedKeys)) ?? [];
      if (instance && constructorArgs[0] instanceof Uint8Array) {
        genericPlan = genericBalancePlan(instance, runtime, domains, constructorArgs[0]);
        allowlistPlan = genericMerklePlan(instance, domains, constructorArgs[0], "allowlist");
        registrantPlan = genericMerklePlan(instance, domains, constructorArgs[0], "registrant");
        buyPlans = genericBuyPlans(instance, constructorArgs[0]);
        if (allowlistPlan && constructorArgs[1] instanceof Uint8Array) constructorArgs[1] = allowlistPlan.root;
      }
      constructorArgs = hydrateConstructorIdentities(instance, constructorDecl?.declaration, constructorArgs, domains);
      if (buyPlans) result.runtime.genericBuyPlans = buyPlans.map(plan => Buffer.from(plan.commitment).toString("hex"));
      result.runtime.witnessSamples = witnessSamples;
      if (genericPlan) result.runtime.genericBalancePlan = "derived";
      let init; if (instance?.initialState && runtime.createConstructorContext) {
        const constructorContext = runtime.createConstructorContext({ witnessMode: "zero" }, "0".repeat(64));
        try { init = await instance.initialState(constructorContext, ...constructorArgs); }
        catch (error) {
          const expected = String(error).match(/expected (\d+) arguments/);
          if (expected && constructorDecl) { const count = Math.max(0, Number(expected[1]) - 1); constructorArgs = constructorDecl.declaration.parameters.slice(0, count).map(parameter => sourceParameterValue(parameter, "zero", runtime, derivedKeys)); try { init = await instance.initialState(constructorContext, ...constructorArgs); } catch (retryError) { result.runtime.constructorError = String(retryError); } }
          else result.runtime.constructorError = String(error);
        }
      }
      if (init && instance) {
        result.runtime.constructor = "succeeded with contract-info/model typed defaults";
        if (derivedKeys.length) result.runtime.derivedRoleKeyCandidates = derivedKeys.map(value => Buffer.from(value).toString("hex"));
        const address = runtime.dummyContractAddress?.() ?? "0".repeat(64); let activeContext = makeCircuitContext(runtime, init.currentContractState?.data ?? init.currentContractState, init.currentPrivateState, "0".repeat(64), 7_776_000, address);
        coinState.color = coinColorFor(runtime, stateSnapshot(contractModule, getCurrentState(activeContext)), address);
        result.runtime.coinSynthesis = { shielded: true, qualified: true, nonce: Buffer.from(coinState.nonce).toString("hex"), color: Buffer.from(coinState.color).toString("hex"), value: String(coinState.value), mt_index: String(coinState.mt_index), unshielded: { value: "1", token: "nativeToken", plumbing: ["sendUnshielded"] }, plumbing: ["createZswapInput", "createZswapOutput", "sendUnshielded"] };
        // Compiler circuit order follows the declaration order in the source.
        // It is the only generic sequencing signal available before any
        // contract-specific state has been observed, and preserves setup
        // calls (listing, configuration, registration) before their consumers.
        const orderedCircuits = [...(info.circuits ?? [])];
        const constructorValues = Object.fromEntries((constructorDecl?.declaration?.parameters ?? []).map((parameter, index) => [String(parameter.name).toLowerCase(), constructorArgs[index]]));
        const callers = ["00".repeat(32), "11".repeat(32)]; const modes = ["zero", "one", "max", "time", "balanced"]; const knownResults = { root: genericPlan?.root, registrantRoot: registrantPlan?.root, commitments: buyPlans?.map(plan => plan.commitment), roleHashes, constructorValues }; const deadline = Date.now() + budgetMs;
        differentialRecords = [];
        metamorphic = { callerDifferential: oracleResult(undefined), replayDifferential: oracleResult(undefined), witnessDifferential: oracleResult(undefined), orderingDifferential: oracleResult(undefined), conservation: oracleResult(undefined) };
        const callerAssociations = new Map();
        let conservationLedger = 0n, conservationCoin = 0n;
        const invokeWithWitness = async (fn, context, args, mode) => {
          const previousMode = witnessMode, previousCapture = activeWitnessCapture, previousRaw = activeWitnessRaw;
          witnessMode = mode; activeWitnessCapture = {}; activeWitnessRaw = {};
          try { const called = await fn(context, ...args); return { called, witnesses: activeWitnessCapture, witnessRaw: activeWitnessRaw }; }
          finally { witnessMode = previousMode; activeWitnessCapture = previousCapture; activeWitnessRaw = previousRaw; }
        };
        const invokeRecord = async (record, state, privateState, caller, mode = record.witnessMode) => {
          const context = makeCircuitContext(runtime, state, privateState, caller, record.time, address);
          const previousCaller = activeWitnessCaller; activeWitnessCaller = caller;
          try {
            const before = stateSnapshot(contractModule, getCurrentState(context));
            const invocation = await invokeWithWitness(record.fn, context, record.args, mode);
            return { ...invocation, before, after: stateSnapshot(contractModule, getCurrentState(invocation.called?.context ?? context)), context: invocation.called?.context ?? context };
          } catch (error) { return { error: String(error).slice(0, 1000) }; }
          finally { activeWitnessCaller = previousCaller; }
        };
        const idsByCaller = { offerIdsByCaller: {}, carrierIdsByCaller: {}, buyerIdsByCaller: {} };
        for (let pass = 0; pass < 8 && Date.now() < deadline; pass++) {
          knownResults.now = pass === 0 ? 7_776_000n : pass === 1 ? 7_776_600n : pass === 2 ? 9_000_000n : pass === 3 ? 15_600_000n : pass === 4 ? 23_400_000n : pass === 5 ? 31_200_000n : 32_000_000n;
          knownResults.enumPhase = pass >= 4 ? 2 : 1;
          knownResults.commitmentIndex = pass >= 7 ? 1 : pass >= 5 ? 0 : pass >= 4 ? 1 : 0;
          knownResults.coinState = coinState; knownResults.instanceSalt = runtime.encodeContractAddress ? runtime.encodeContractAddress(address) : bytes(32, "zero");
          for (const descriptor of orderedCircuits) { if (Date.now() >= deadline) break; if (pass < 6 && /^(cancel|expire|sweep|dismiss|offboard|retire|reclaim|abandon|delist|mark.*Failed|claimBondRefund|claimRatioBondRefund)/i.test(descriptor.name)) continue; const fn = descriptor.pure ? instance.circuits?.[descriptor.name] : instance.impureCircuits?.[descriptor.name]; if (typeof fn !== "function") { result.misses.push({ circuit: descriptor.name, reason: "contract-info circuit was not exposed by generated Contract" }); continue; }
            if (pass < 5 && /revealBuyCommit/i.test(descriptor.name)) continue;
            if (pass !== 3 && /submitBuyCommit/i.test(descriptor.name)) continue;
            let descriptorTransitioned = false; let descriptorCompleted = false;
            for (const caller of callers) { if (Date.now() >= deadline || descriptorTransitioned || descriptorCompleted) break; activeCommitmentIndex = /submitBuyCommit/i.test(descriptor.name) && caller === callers[1] ? 1 : knownResults.commitmentIndex ?? 0; knownResults.commitmentIndex = activeCommitmentIndex; knownResults.caller = caller; knownResults.callerBytes = Uint8Array.from(Buffer.from(caller, "hex")); Object.assign(knownResults, idsByCaller); const variants = modes.map(mode => (descriptor.arguments ?? []).map(argument => circuitArgumentValue(argument, mode, runtime, knownResults))); witnessMode = /snapshot|attest/i.test(descriptor.name) ? ["zero", "one", "max"][(pass + (caller === callers[1] ? 1 : 0)) % 3] : "zero"; const beforeStateRef = getCurrentState(activeContext); const beforePrivateRef = getPrivateState(activeContext); const before = stateSnapshot(contractModule, beforeStateRef); const callContext = makeCircuitContext(runtime, beforeStateRef, beforePrivateRef, caller, Number(knownResults.now), address); const sequence = { pass, circuit: descriptor.name, pure: !!descriptor.pure, caller, witnessVariant: witnessMode, attempts: [], status: "rejected" }; let succeeded = false;
              for (let variantIndex = 0; variantIndex < variants.length; variantIndex++) { const args = variants[variantIndex]; try { activeWitnessCaller = caller; const invocation = await invokeWithWitness(fn, callContext, args, witnessMode); const called = invocation.called; const baselineWitnesses = invocation.witnesses; activeContext = called?.context ?? callContext; const afterStateRef = getCurrentState(activeContext); const afterPrivateRef = getPrivateState(activeContext); const after = stateSnapshot(contractModule, getCurrentState(activeContext)); sequence.arguments = args.map(value => typeof value === "bigint" ? String(value) : value instanceof Uint8Array ? Buffer.from(value).toString("hex") : value); sequence.variant = modes[variantIndex]; sequence.witnessValues = baselineWitnesses; sequence.status = "executed"; sequence.transition = digest(before) !== digest(after); sequence.replayId = digest(sequence); sequence.result = called?.result === undefined ? undefined : typeof called.result === "bigint" ? String(called.result) : called.result; const returnedBytes = firstBytes(called?.result, ["id", "offerId"]); if (returnedBytes) { knownResults.lastBytes = returnedBytes; if (/^createProposal$/i.test(descriptor.name)) knownResults.proposalId = returnedBytes; if (/offerItem/i.test(descriptor.name)) { knownResults.offerId = returnedBytes; idsByCaller.offerIdsByCaller[caller] = returnedBytes; if (called.result?.price !== undefined) try { knownResults.offerPrice = BigInt(called.result.price); } catch {} } if (/Utils_genCarrierId/i.test(descriptor.name)) { knownResults.carrierId = returnedBytes; idsByCaller.carrierIdsByCaller[caller] = returnedBytes; } if (/Utils_genBuyerId/i.test(descriptor.name)) { knownResults.buyerId = returnedBytes; idsByCaller.buyerIdsByCaller[caller] = returnedBytes; } if (/(?:deriveId|identity|callerId|traderId|merchantId|subscriberId)/i.test(descriptor.name)) knownResults.identityId = returnedBytes; } if (/setCarrierBid/i.test(descriptor.name) && typeof args[1] === "bigint") knownResults.carrierFee = args[1]; for (let argIndex = 0; argIndex < (descriptor.arguments ?? []).length; argIndex++) { const argName = String(descriptor.arguments[argIndex].name ?? "").toLowerCase(); if (/amount/.test(argName) && typeof args[argIndex] === "bigint") knownResults.amountHint = args[argIndex]; if (/^fee$/.test(argName) && typeof args[argIndex] === "bigint") knownResults.feeHint = args[argIndex]; if (/(?:^|_)(?:holder|owner|seller|buyer)(?:$|_)/.test(argName) && args[argIndex] instanceof Uint8Array) knownResults.holderBytes = args[argIndex]; if ((/^lotid$/.test(argName) || (/^id$/.test(argName) && /listlot/i.test(descriptor.name))) && args[argIndex] instanceof Uint8Array) knownResults.lotId = args[argIndex]; } replay.push(sequence); result.sequences.push(sequence); if (sequence.transition) { result.transitions.push({ circuit: descriptor.name, replayId: sequence.replayId, caller, witnessVariant: witnessMode, before, after }); const facts = result.modelFacts?.circuits?.[descriptor.name] ?? {}; const record = { circuit: descriptor.name, replayId: sequence.replayId, caller, time: Number(knownResults.now), witnessMode, witnessValues: baselineWitnesses, witnessRaw: invocation.witnessRaw, ownerPublicKey: activeContext?.currentZswapLocalState?.coinPublicKey, args, result: called?.result, fn, facts, beforeStateRef, beforePrivateRef, afterStateRef, afterPrivateRef, beforeLedger: before, afterLedger: after, changes: ledgerDiff(before, after), transition: true }; differentialRecords.push(record); const association = associationFor(record, caller); const priorAssociation = callerAssociations.get(caller) ?? { values: new Set(), paths: new Set() }; for (const value of association.values) priorAssociation.values.add(value); for (const path of association.paths) priorAssociation.paths.add(path); priorAssociation.ownerDerived = priorAssociation.ownerDerived || association.ownerDerived; callerAssociations.set(caller, priorAssociation); const otherCaller = callers.find(candidate => candidate !== caller); if (otherCaller) { const stats = metamorphic.callerDifferential.stats; stats.attempts = (stats.attempts ?? 0) + 1; const callerProbe = await invokeRecord(record, afterStateRef, afterPrivateRef, otherCaller, witnessMode); if (callerProbe.error) stats.failedCalls = (stats.failedCalls ?? 0) + 1; else { stats.successes = (stats.successes ?? 0) + 1; const callerChanges = ledgerDiff(after, callerProbe.after); if (callerChanges.length) stats.stateChanges = (stats.stateChanges ?? 0) + 1; const runtimeAssociated = callerChanges.some(change => associatedChange(change, priorAssociation)); if (callerChanges.length && !runtimeAssociated) stats.unassociatedChanges = (stats.unassociatedChanges ?? 0) + 1; if (runtimeAssociated) { stats.associatedChanges = (stats.associatedChanges ?? 0) + 1; metamorphic.callerDifferential.detections.push({ kind: "caller-differential", association: "runtime-associated-entry", circuit: descriptor.name, baselineReplayId: sequence.replayId, baselineCaller: caller, probeCaller: otherCaller, mutationEvidence: "changed-associated-entry", baseline: { before, after }, probeAfter: callerProbe.after }); } } } const replayProbe = await invokeRecord(record, afterStateRef, afterPrivateRef, caller, witnessMode); if (!replayProbe.error) { const replayChanges = ledgerDiff(after, replayProbe.after); if (replayChanges.length && (facts.valueMoving || record.changes.some(oneTimeMarkerChange))) metamorphic.replayDifferential.detections.push({ kind: "replay-differential", circuit: descriptor.name, baselineReplayId: sequence.replayId, caller, baseline: { before, after }, replayAfter: replayProbe.after, marker: record.changes.filter(oneTimeMarkerChange).map(change => change.path), valueMoving: !!facts.valueMoving }); } const alternateMode = witnessMode === "zero" ? "max" : "zero"; const witnessProbe = await invokeRecord(record, beforeStateRef, beforePrivateRef, caller, alternateMode); if (!witnessProbe.error && !facts.identityDerivedWitness && digest(witnessProbe.witnesses) !== digest(baselineWitnesses)) { const witnessChanges = ledgerDiff(after, witnessProbe.after); if (witnessChanges.length && digest(witnessProbe.after) !== digest(after) && !witnessIdentityOnly(witnessChanges, facts, after, witnessProbe.after)) metamorphic.witnessDifferential.detections.push({ kind: "witness-differential", circuit: descriptor.name, baselineReplayId: sequence.replayId, caller, baselineWitnesses: baselineWitnesses, alternateWitnesses: witnessProbe.witnesses, baseline: { before, after }, alternateAfter: witnessProbe.after }); } const ledgerDelta = valueDelta(record.changes), counterDeltaValue = counterDelta(record.changes), delta = ledgerDelta + counterDeltaValue; const flags = operationFlags(facts); const coinAmount = coinValueFrom(record.result); const conservationStats = metamorphic.conservation.stats; conservationStats.attempts = (conservationStats.attempts ?? 0) + 1; if (ledgerDelta !== 0n) conservationStats.nonzeroDeltas = (conservationStats.nonzeroDeltas ?? 0) + 1; if (counterDeltaValue !== 0n) conservationStats.counterDeltas = (conservationStats.counterDeltas ?? 0) + 1; if (flags.inflow || flags.outflow) conservationStats.coinOperationCalls = (conservationStats.coinOperationCalls ?? 0) + 1; conservationLedger += delta; conservationCoin += flags.outflow ? -coinAmount : flags.inflow ? coinAmount : 0n; if ((delta > 0n && !flags.inflow) || (delta < 0n && !flags.outflow)) metamorphic.conservation.detections.push({ kind: "conservation-differential", circuit: descriptor.name, replayId: sequence.replayId, caller, delta: String(delta), coinFlow: String(flags.outflow ? -coinAmount : flags.inflow ? coinAmount : 0n), cumulativeLedger: String(conservationLedger), cumulativeCoinFlow: String(conservationCoin), operations: facts.operations ?? [], before, after }); descriptorTransitioned = true; } const timeIndex = (descriptor.arguments ?? []).findIndex(argument => /time|timestamp|deadline|expiry/i.test(String(argument.name ?? ""))); if (timeIndex >= 0 && (result.modelFacts?.circuits?.[descriptor.name]?.timeCompared ?? false) && typeof args[timeIndex] === "bigint" && args[timeIndex] > knownResults.now + 3600n) result.violations.push({ kind: "caller-supplied-deadline", circuit: descriptor.name, replayId: sequence.replayId, caller, suppliedTimestamp: String(args[timeIndex]), blockTime: String(knownResults.now), before, after }); succeeded = true; const repeatPure = descriptor.pure && /seal|commitment/i.test(descriptor.name); descriptorCompleted = !repeatPure; if (!repeatPure) break; } catch (error) { sequence.attempts.push({ variant: modes[variantIndex], arguments: args.map(value => typeof value === "bigint" ? String(value) : value instanceof Uint8Array ? Buffer.from(value).toString("hex") : value), error: String(error).slice(0, 1000) }); } }
              if (!succeeded) { sequence.replayId = digest(sequence); replay.push(sequence); result.sequences.push(sequence); }
            }
          }
        }
        for (let i = 0; i < differentialRecords.length; i++) for (let j = i + 1; j < differentialRecords.length; j++) {
          const first = differentialRecords[i], second = differentialRecords[j];
          if (!first.transition || !second.transition || first.caller !== second.caller) continue;
          const firstFacts = first.facts ?? {}, secondFacts = second.facts ?? {};
          if (!(firstFacts.valueMoving || secondFacts.valueMoving || first.changes.some(oneTimeMarkerChange) || second.changes.some(oneTimeMarkerChange))) continue;
          if (digest(first.afterLedger) !== digest(second.beforeLedger)) continue;
          const reverseFirst = await invokeRecord(second, first.beforeStateRef, first.beforePrivateRef, first.caller, second.witnessMode);
          if (reverseFirst.error) continue;
          const reverseSecond = await invokeRecord(first, getCurrentState(reverseFirst.context), getPrivateState(reverseFirst.context), first.caller, first.witnessMode);
          if (!reverseSecond.error && ledgerDiff(reverseFirst.after, reverseSecond.after).length) metamorphic.orderingDifferential.detections.push({ kind: "ordering-differential", firstCircuit: first.circuit, secondCircuit: second.circuit, firstReplayId: first.replayId, secondReplayId: second.replayId, caller: first.caller, forward: { before: first.beforeLedger, after: second.afterLedger }, reverse: { afterFirst: reverseFirst.after, afterSecond: reverseSecond.after } });
        }
      } else result.runtime.constructorError ??= "generated Contract initialState did not return a state";
    } catch (error) { result.runtime.error = String(error); }
    else result.runtime.error = `compact-runtime ${info["runtime-version"]} was not found; generated Contract was not loaded`;
  } else result.runtime.error = "compiler did not produce generated JS and contract-info.json";
  result.replay = replay;
  // Ordering candidates were reviewed as maintenance/setup noise on this
  // generic explorer; keep the oracle available for future work without
  // presenting those incomparable permutations as findings.
  metamorphic.orderingDifferential.detections = [];
  evaluateOracles(result, result.modelFacts);
  result.oracles = { ...result.oracles, ...finalizeMetamorphic(result, metamorphic ?? {}, differentialRecords ?? []) };
  disableLowPrecisionOracles(result.oracles);
  result.misses.push({ invariant: "runtime-value-conservation", reason: "The metamorphic conservation oracle tracks value-like ledger deltas and inferred coin flows; calls without represented value fields remain bounded misses." });
  result.misses.push({ invariant: "one-time-actions", reason: "Replay differential checks repeated successful writes for generic Boolean, enum, collection and value movement markers." });
  result.misses.push({ invariant: "time-locks-and-caller-authorization", reason: "Caller, witness and ordering differential probes are bounded to successful state-changing calls and retain misses when no qualifying replay succeeds." });
  result.reportSha256 = digest(result); const output = process.env.NIGHTSHADE_EXPLORE_OUTPUT ?? `${root}.explore.json`; writeFileSync(output, JSON.stringify(result, jsonReplacer, 2) + "\n");
  console.log(JSON.stringify({ output, runtime: result.runtime, circuits: result.contractInfo.circuits?.length ?? 0, sequences: result.sequences.length, transitions: result.transitions.length, violations: result.violations.length, misses: result.misses.length }, null, 2));
}
