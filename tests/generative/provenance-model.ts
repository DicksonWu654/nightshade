/**
 * Owned linear fixture grammar and independent structural property contract.
 * No analyzer transfers, semantic effects, detectors or generated code are used
 * to compute expectations. Tags describe dependency tracking, not leakage or
 * security labels; the designated guard means completion since a relevant write.
 */
export type ProvenanceOperation =
  | { kind: "put"; value: "first" | "second" | "sum" | "zero"; route: "direct" | "nested" }
  | { kind: "snapshot" | "read" | "guard" | "refresh" | "unrelated" };

export interface ProvenanceCase {
  schemaVersion: "nightshade-provenance-case-1";
  seed: number;
  operations: ProvenanceOperation[];
}

export interface ProvenanceTag {
  source: "first" | "second";
  form: "raw" | "derived";
}

export interface ExpectedProvenanceWrite {
  root: "stored" | "authorized" | "unrelated";
  before: ProvenanceTag[];
  after: ProvenanceTag[];
  guarded: boolean;
  callPath: string[];
}

export interface ProvenanceExpectations {
  writes: ExpectedProvenanceWrite[];
  /** Each checkpoint contains [current stored, saved scalar, clean unrelated]. */
  checkpoints: [ProvenanceTag[], ProvenanceTag[], ProvenanceTag[]][];
}

const schemaVersion = "nightshade-provenance-case-1";
function object(value: unknown, keys: readonly string[], name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`${name} must be a plain object`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== "string" || !keys.includes(key))) throw new Error(`${name} has missing or unknown fields`);
  for (const key of keys) if (!("value" in Object.getOwnPropertyDescriptor(value, key)!)) throw new Error(`${name} requires data fields`);
  return value as Record<string, unknown>;
}

function natural(value: unknown, maximum: number, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < 0 || value > maximum) throw new Error(`${name} must be an integer in 0..${maximum}`);
  return value;
}

export function validateProvenanceCase(value: unknown): ProvenanceCase {
  const item = object(value, ["schemaVersion", "seed", "operations"], "provenance case");
  if (item.schemaVersion !== schemaVersion) throw new Error("Unsupported provenance case schema");
  const seed = natural(item.seed, 0xffffffff, "seed");
  if (!Array.isArray(item.operations) || Object.getPrototypeOf(item.operations) !== Array.prototype || item.operations.length > 12
    || Reflect.ownKeys(item.operations).length !== item.operations.length + 1) throw new Error("operations must be a dense array of at most 12 items");
  for (let index = 0; index < item.operations.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(item.operations, index);
    if (!descriptor || !("value" in descriptor)) throw new Error("operations must contain indexed data fields");
  }
  const operations = item.operations.map((value: unknown): ProvenanceOperation => {
    if (!value || typeof value !== "object") throw new Error("Invalid provenance operation");
    const kind = Object.getOwnPropertyDescriptor(value, "kind");
    if (!kind || !("value" in kind)) throw new Error("Operation requires a kind data field");
    if (kind.value === "put") {
      const operation = object(value, ["kind", "value", "route"], "put");
      if (!["first", "second", "sum", "zero"].includes(operation.value as string) || !["direct", "nested"].includes(operation.route as string)) throw new Error("Unsupported put expression or route");
      return { kind: "put", value: operation.value as "first" | "second" | "sum" | "zero", route: operation.route as "direct" | "nested" };
    }
    if (!["snapshot", "read", "guard", "refresh", "unrelated"].includes(kind.value)) throw new Error("Unsupported provenance operation");
    object(value, ["kind"], "operation");
    return { kind: kind.value };
  });
  return { schemaVersion, seed, operations };
}

/** Fixed uint32 LCG. Generation never accepts names, source text or call targets. */
export function generateProvenanceCase(seed: number, steps: number): ProvenanceCase {
  natural(seed, 0xffffffff, "seed");
  natural(steps, 12, "steps");
  let state = seed;
  const next = (): number => (state = (Math.imul(state, 1664525) + 1013904223) >>> 0) >>> 16;
  const operations: ProvenanceOperation[] = Array.from({ length: steps }, () => {
    const selected = next() % 9;
    if (selected < 4) return { kind: "put", value: (["first", "second", "sum", "zero"] as const)[selected], route: next() % 2 ? "nested" : "direct" };
    return { kind: (["snapshot", "read", "guard", "refresh", "unrelated"] as const)[selected - 4] };
  });
  return { schemaVersion, seed, operations };
}

export function renderProvenanceCase(value: ProvenanceCase): string {
  const item = validateProvenanceCase(value);
  const operations = item.operations.length ? item.operations : [{ kind: "read" } as const];
  let saved = "snapshot0";
  const lines = ["  stored = 0 as Field;", "  authorized = true;", "  unrelated = 0 as Field;", "  const snapshot0 = stored;"];
  operations.forEach((operation, index) => {
    if (operation.kind === "put") {
      const expression = operation.value === "zero" ? "0 as Field" : operation.value === "sum" ? "first + second" : operation.value;
      lines.push(`  ${operation.route === "nested" ? "outerPut" : "put"}(${expression});`);
    } else if (operation.kind === "snapshot") {
      saved = `snapshot${index + 1}`;
      lines.push(`  const ${saved} = stored;`);
    } else if (operation.kind === "guard") lines.push("  guard();");
    else if (operation.kind === "refresh") lines.push("  authorized = true;");
    else if (operation.kind === "unrelated") lines.push("  unrelated = 0 as Field;");
    lines.push("  nestedRead();", `  const checkpoint${index} = [nestedRead(), ${saved}, unrelated];`);
  });
  lines.push(`  return [${operations.map((_, index) => `checkpoint${index}`).join(", ")}];`);
  return `pragma language_version 0.26.0;
export ledger stored: Field;
export ledger authorized: Boolean;
export ledger unrelated: Field;
circuit guard(): [] { assert(authorized, "owned guard"); }
circuit put(value: Field): [] { stored = disclose(value); }
circuit outerPut(value: Field): [] { put(value); }
circuit leafRead(): Field { return stored; }
circuit nestedRead(): Field { return leafRead(); }
export circuit entry(first: Field, second: Field): [${operations.map(() => "[Field, Field, Field]").join(", ")}] {
${lines.join("\n")}
}
`;
}

export function expectedProvenance(value: ProvenanceCase): ProvenanceExpectations {
  const item = validateProvenanceCase(value);
  let stored: ProvenanceTag[] = [];
  let saved: ProvenanceTag[] = [];
  let guarded = false;
  const copy = (tags: ProvenanceTag[]): ProvenanceTag[] => tags.map(tag => ({ ...tag }));
  const writes: ExpectedProvenanceWrite[] = (["stored", "authorized", "unrelated"] as const).map(root => ({ root, before: [], after: [], guarded: false, callPath: ["entry"] }));
  const checkpoints: ProvenanceExpectations["checkpoints"] = [];
  for (const operation of item.operations) {
    if (operation.kind === "put") {
      const tags: ProvenanceTag[] = operation.value === "zero" ? [] : operation.value === "sum"
        ? [{ source: "first", form: "derived" }, { source: "second", form: "derived" }] : [{ source: operation.value, form: "raw" }];
      writes.push({ root: "stored", before: copy(stored), after: copy(tags), guarded, callPath: operation.route === "nested" ? ["entry", "outerPut", "put"] : ["entry", "put"] });
      stored = tags;
    } else if (operation.kind === "snapshot") saved = copy(stored);
    else if (operation.kind === "guard") guarded = true;
    else if (operation.kind === "refresh" || operation.kind === "unrelated") {
      writes.push({ root: operation.kind === "refresh" ? "authorized" : "unrelated", before: [], after: [], guarded, callPath: ["entry"] });
      // The fixture's designated guard reads only authorized. This dependency
      // contract is fixed here, never obtained from Program's inferred effects.
      if (operation.kind === "refresh") guarded = false;
    }
    checkpoints.push([copy(stored), copy(saved), []]);
  }
  return { writes, checkpoints: checkpoints.length ? checkpoints : [[[], [], []]] };
}
