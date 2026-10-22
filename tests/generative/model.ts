/**
 * A deliberately bounded language of owned, synthetic Compact programs.
 *
 * This concrete oracle does not import the analyzer, its collection domain or
 * generated compiler output. It specifies only this small initialized fragment;
 * it is not an oracle for arbitrary Compact or for proof/transaction execution.
 */
export type Operation =
  | { kind: "reset" }
  | { kind: "insert"; key: number }
  | { kind: "remove"; key: number }
  | { kind: "write"; value: number }
  | { kind: "unrelated"; value: number }
  | { kind: "snapshot" }
  | { kind: "read"; key: number }
  | { kind: "conditional"; key: number; value: number };

export interface GeneratedCase {
  schemaVersion: "nightshade-generated-case-1";
  seed: number;
  operations: Operation[];
}

const schemaVersion = "nightshade-generated-case-1";
const maximumSteps = 32;
const maximumKey = 7;
const maximumValue = 65535;

function integer(value: unknown, maximum: number, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || Object.is(value, -0) || value < 0 || value > maximum) {
    throw new Error(`${label} must be an integer in 0..${maximum}`);
  }
  return value;
}

function record(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new Error(`${label} must be a plain object`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some(key => typeof key !== "string" || !keys.includes(key))) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in property)) throw new Error(`${label}.${key} must be a data field`);
  }
  return value as Record<string, unknown>;
}

/** Validate and copy untrusted replay data; do not accept embedded source text. */
export function validateCase(value: unknown): GeneratedCase {
  const item = record(value, ["schemaVersion", "seed", "operations"], "case");
  if (item.schemaVersion !== schemaVersion) throw new Error("unsupported generated-case schema");
  const seed = integer(item.seed, 0xffffffff, "seed");
  if (!Array.isArray(item.operations) || Object.getPrototypeOf(item.operations) !== Array.prototype || item.operations.length > maximumSteps) {
    throw new Error(`operations must be an array of at most ${maximumSteps} items`);
  }
  // Do not silently lose sparse entries, accept hidden fields or invoke accessors.
  if (Reflect.ownKeys(item.operations).length !== item.operations.length + 1) throw new Error("operations must be a dense array without extra fields");
  for (let index = 0; index < item.operations.length; index++) {
    const property = Object.getOwnPropertyDescriptor(item.operations, index);
    if (!property || !("value" in property)) throw new Error("operations must contain data fields at each index");
  }
  const operations: Operation[] = item.operations.map((raw: unknown, index: number): Operation => {
    if (raw === null || typeof raw !== "object") throw new Error(`operation ${index} must be an object`);
    const descriptor = Object.getOwnPropertyDescriptor(raw, "kind");
    if (!descriptor || !("value" in descriptor)) throw new Error(`operation ${index} requires a kind data field`);
    const kind: unknown = descriptor.value;
    const label = `operation ${index}`;
    switch (kind) {
      case "reset": case "snapshot":
        record(raw, ["kind"], label);
        return { kind };
      case "insert": case "remove": case "read": {
        const operation = record(raw, ["kind", "key"], label);
        return { kind, key: integer(operation.key, maximumKey, `${label}.key`) };
      }
      case "write": case "unrelated": {
        const operation = record(raw, ["kind", "value"], label);
        return { kind, value: integer(operation.value, maximumValue, `${label}.value`) };
      }
      case "conditional": {
        const operation = record(raw, ["kind", "key", "value"], label);
        return {
          kind, key: integer(operation.key, maximumKey, `${label}.key`),
          value: integer(operation.value, maximumValue, `${label}.value`),
        };
      }
      default: throw new Error(`unsupported operation kind at ${index}`);
    }
  });
  return { schemaVersion, seed, operations };
}

/** Fixed uint32 LCG: its output depends only on seed and step count. */
export function generateCase(seed: number, steps: number): GeneratedCase {
  integer(seed, 0xffffffff, "seed");
  integer(steps, maximumSteps, "steps");
  if (steps === 0) throw new Error("steps must be in 1..32");
  let state = seed;
  const next = (): number => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  const keys = (): number => (next() >>> 16) % (maximumKey + 1);
  const values = (): number => {
    const sample = next();
    const boundaries = [0, 1, 255, 256, maximumValue];
    return sample % 3 === 0 ? boundaries[(sample >>> 16) % boundaries.length] : sample >>> 16;
  };
  const operations: Operation[] = [];
  for (let index = 0; index < steps; index++) {
    switch ((next() >>> 16) % 8) {
      case 0: operations.push({ kind: "reset" }); break;
      case 1: operations.push({ kind: "insert", key: keys() }); break;
      case 2: operations.push({ kind: "remove", key: keys() }); break;
      case 3: operations.push({ kind: "write", value: values() }); break;
      case 4: operations.push({ kind: "unrelated", value: values() }); break;
      case 5: operations.push({ kind: "snapshot" }); break;
      case 6: operations.push({ kind: "read", key: keys() }); break;
      case 7: operations.push({ kind: "conditional", key: keys(), value: values() }); break;
    }
  }
  return { schemaVersion, seed, operations };
}

/**
 * Checkpoint layout: [scalar, member(key), cardinality, savedScalar, unrelated].
 * A keyless operation observes membership at key 0. Empty cases still return
 * one checkpoint, so removing all operations remains a usable regression.
 */
export function renderCase(value: GeneratedCase): string {
  const item = validateCase(value);
  const observationType = "[Field, Boolean, Uint<64>, Field, Field]";
  const operations = item.operations.length ? item.operations : [{ kind: "read", key: 0 } as const];
  const body: string[] = [
    "  stored = 0 as Field;", "  unrelated = 0 as Field;", "  members.resetToDefault();", "  const snapshot0 = stored;",
  ];
  let snapshot = "snapshot0";
  operations.forEach((operation, index) => {
    switch (operation.kind) {
      case "reset": body.push("  members.resetToDefault();"); break;
      case "insert": body.push(`  add(${operation.key} as Field);`); break;
      case "remove": body.push(`  members.remove(${operation.key} as Field);`); break;
      case "write": body.push(`  setStored(${operation.value} as Field);`); break;
      case "unrelated": body.push(`  unrelated = ${operation.value} as Field;`); break;
      case "snapshot":
        snapshot = `saved${index}`;
        body.push(`  const ${snapshot} = stored;`);
        break;
      case "conditional":
        body.push(`  if (disclose(flag)) { setStored(${operation.value} as Field); add(${operation.key} as Field); }`);
        break;
      case "read": break;
    }
    const key = "key" in operation ? operation.key : 0;
    // Repeat identical calls to exercise cache reuse and nested read replay.
    body.push(`  observe(${key} as Field, ${snapshot});`);
    body.push(`  const checkpoint${index} = observe(${key} as Field, ${snapshot});`);
  });
  body.push(`  return [${operations.map((_, index) => `checkpoint${index}`).join(", ")}];`);
  return `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger stored: Field;
export ledger unrelated: Field;
export ledger members: Set<Field>;
circuit leafRead(): Field { return stored; }
circuit nestedRead(): Field { return leafRead(); }
circuit setStored(value: Field): [] { stored = disclose(value); }
circuit add(key: Field): [] { members.insert(disclose(key)); }
circuit observe(key: Field, saved: Field): ${observationType} {
  return [nestedRead(), members.member(disclose(key)), members.size(), saved, unrelated];
}
export circuit entry(flag: Boolean): [${operations.map(() => observationType).join(", ")}] {
${body.join("\n")}
}
`;
}

export interface FlagObservations {
  flag: boolean;
  observations: string[][];
}

/** Preserve the input/trace association, including coincident output traces. */
export function expectedFlagObservations(value: GeneratedCase): FlagObservations[] {
  const item = validateCase(value);
  return [false, true].map(flag => {
    const members = new Set<bigint>();
    let scalar = 0n;
    let unrelated = 0n;
    let saved = 0n;
    const observations: string[][] = [];
    for (const operation of item.operations) {
      switch (operation.kind) {
        case "reset": members.clear(); break;
        case "insert": members.add(BigInt(operation.key)); break;
        case "remove": members.delete(BigInt(operation.key)); break;
        case "write": scalar = BigInt(operation.value); break;
        case "unrelated": unrelated = BigInt(operation.value); break;
        case "snapshot": saved = scalar; break;
        case "conditional":
          if (flag) { scalar = BigInt(operation.value); members.add(BigInt(operation.key)); }
          break;
        case "read": break;
      }
      const key = "key" in operation ? BigInt(operation.key) : 0n;
      observations.push([String(scalar), String(members.has(key)), String(members.size), String(saved), String(unrelated)]);
    }
    return { flag, observations: observations.length ? observations : [["0", "false", "0", "0", "0"]] };
  });
}

/** Exact reachable concrete traces, retaining the original public helper API. */
export function expectedObservations(value: GeneratedCase): string[][][] {
  const traces = expectedFlagObservations(value).map(outcome => outcome.observations);
  return [...new Map(traces.map(trace => [JSON.stringify(trace), trace])).values()];
}

/**
 * Deterministic proposals only: the caller must rerun its failure predicate.
 * Each candidate decreases operation count or the sum of numeric operands.
 */
export function shrinkCandidates(value: GeneratedCase): GeneratedCase[] {
  const item = validateCase(value);
  const candidates: GeneratedCase[] = [];
  const seen = new Set([JSON.stringify(item)]);
  const add = (operations: Operation[]): void => {
    const candidate = validateCase({ ...item, operations });
    const identity = JSON.stringify(candidate);
    if (!seen.has(identity)) { seen.add(identity); candidates.push(candidate); }
  };
  if (item.operations.length) add([]);
  for (let width = Math.ceil(item.operations.length / 2); width >= 1; width = Math.floor(width / 2)) {
    for (let start = 0; start < item.operations.length; start += width) {
      add([...item.operations.slice(0, start), ...item.operations.slice(start + width)]);
    }
  }
  item.operations.forEach((operation, index) => {
    for (const field of ["key", "value"] as const) {
      if (!(field in operation)) continue;
      const original = (operation as unknown as Record<string, number>)[field];
      for (const replacement of new Set([0, Math.floor(original / 2)])) {
        if (replacement === original) continue;
        add(item.operations.map((entry, at) => at === index ? { ...entry, [field]: replacement } : entry));
      }
    }
  });
  return candidates;
}
