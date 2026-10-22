import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import type { Detector } from "../src/detectors/types.js";
import { callerSuppliedTimeReview, unassertedSecurityResult, witnessDerivedValueReview } from "../src/detectors/development-patterns.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = "pragma language_version >= 0.23; import CompactStandardLibrary;\n";
function check(rule: Detector, source: string, expected: number, prefix = header): void {
  withFiles({ "main.compact": prefix + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.filter(item => item.detectorId === rule.id).length, expected, source);
    for (const item of result.findings) {
      const bytes = Buffer.from(prefix + source);
      const fragment = bytes.subarray(item.location.start, item.location.end).toString("utf8");
      assert.ok(fragment.length > 0);
      if (rule.id === callerSuppliedTimeReview.id) assert.ok(fragment.includes(">"), fragment);
      if (rule.id === witnessDerivedValueReview.id) assert.ok(fragment.startsWith("sendUnshielded("), fragment);
      assert.equal(item.metadata.intent, "unknown");
    }
  });
}
const time = (body: string) => `export ledger a: Uint<64>; export ledger b: Boolean;
constructor() { a = 0; b = false; }
export circuit x(v: Uint<64>, choose: Boolean): [] { ${body} }`;

test("development clock review follows resolved values and keeps branch bounds separate", () => {
  check(callerSuppliedTimeReview, time("assert(disclose(v > a), \"condition\"); b = true;"), 1);
  check(callerSuppliedTimeReview, time("assert(blockTimeGte(disclose(v)), \"condition\"); assert(disclose(v > a), \"condition\"); b = true;"), 0);
  check(callerSuppliedTimeReview, time("assert(disclose(v > a), \"condition\"); const c = blockTimeGte(disclose(v)); b = true;"), 1);
  check(callerSuppliedTimeReview, time("assert(blockTimeLt(disclose(v)), \"condition\"); assert(disclose(v > a), \"condition\"); b = true;"), 1);
  check(callerSuppliedTimeReview, time("if (disclose(choose)) { assert(blockTimeGte(disclose(v)), \"condition\"); } else { assert(disclose(v > a), \"condition\"); b = true; }"), 1);
  check(callerSuppliedTimeReview, time("if (disclose(choose)) { assert(blockTimeGte(disclose(v)), \"condition\"); assert(disclose(v > a), \"condition\"); b = true; }"), 0);
  check(callerSuppliedTimeReview, time("assert(disclose(v > a), \"condition\");"), 0);
  check(callerSuppliedTimeReview, time("const c = disclose(v); assert(blockTimeGte(c), \"condition\"); assert(c > a, \"condition\"); b = true;"), 0);
  check(callerSuppliedTimeReview, time("assert(blockTimeGte(disclose(v + 1) as Uint<64>), \"condition\"); assert(disclose(v > a), \"condition\"); b = true;"), 1);
});

const record = (body: string) => `export ledger a: Uint<64>; export ledger m: Map<Uint<64>, Boolean>;
constructor() { a = 0; }
export circuit x(v: Uint<64>): [] { ${body} }`;
test("development predicate review distinguishes recorded predicates from predicate APIs", () => {
  check(unassertedSecurityResult, record("const p = disclose(v > a); m.insert(disclose(v), p);"), 1);
  check(unassertedSecurityResult, record("const p = disclose(v > a); assert(p, \"condition\"); m.insert(disclose(v), p);"), 0);
  check(unassertedSecurityResult, record("const p = disclose(v > a); assert(!p, \"condition\"); m.insert(disclose(v), p);"), 1);
  check(unassertedSecurityResult, `export circuit x(v: Uint<64>, w: Uint<64>): Boolean { return disclose(v > w); }`, 0);
  check(unassertedSecurityResult, record("m.insert(disclose(v), true);"), 0);
  check(unassertedSecurityResult, record('const p = disclose(v > a); m.insert(disclose(v), p); assert(p, "late");'), 1);
  check(unassertedSecurityResult, record("m.member(disclose(v)); m.insert(disclose(v), true);"), 1);
  check(unassertedSecurityResult, record("assert(m.member(disclose(v)), \"condition\"); m.insert(disclose(v), true);"), 0);
});

const payment = (body: string, witness = true) => `export ledger a: Either<ContractAddress, UserAddress>;
export ledger b: Boolean;
constructor() { a = default<Either<ContractAddress, UserAddress>>; b = false; }
${witness ? "witness q(): Either<ContractAddress, UserAddress>;" : "circuit q(): Either<ContractAddress, UserAddress> { return a; }"}
export circuit x(choose: Boolean): [] { const p = disclose(q()); ${body} }`;
const send = "sendUnshielded(default<Bytes<32>>, 1, p);";
test("development recipient review uses witness identity and exact earlier assertions", () => {
  check(witnessDerivedValueReview, payment(send), 1);
  check(witnessDerivedValueReview, payment("assert(p == a, \"condition\"); " + send), 0);
  check(witnessDerivedValueReview, payment("const r = p; assert(r == a, \"condition\"); " + send), 0);
  check(witnessDerivedValueReview, payment("assert(p == p, \"condition\"); " + send), 1);
  check(witnessDerivedValueReview, payment("assert(b, \"condition\"); " + send), 1);
  check(witnessDerivedValueReview, payment("if (disclose(choose)) { assert(p == a, \"condition\"); } else { " + send + " }"), 1);
  check(witnessDerivedValueReview, payment(send, false), 0);
  check(witnessDerivedValueReview, payment(send + " assert(p == a, \"condition\");"), 1);
});

test("development patterns are invariant under renaming, whitespace, comments and string namesakes", () => {
  const original = time('assert(disclose(v > a), "support.insert recovery_round checkIn refundable witnessHint"); b = true;');
  const renamed = original.replaceAll("choose", "switcher").replaceAll("v:", "quantity:").replaceAll("v >", "quantity >")
    .replaceAll("ledger a:", "ledger z:").replaceAll("a =", "z =").replaceAll("> a", "> z");
  for (const source of [original, renamed, renamed.replaceAll(";", ";\n\n"), "// é🙂 Phase Released recovery_round\n" + renamed])
    check(callerSuppliedTimeReview, source, 1);
  const namesake = `circuit blockTimeGte(x: Uint<64>): Boolean { return true; }
export ledger a: Uint<64>; export ledger b: Boolean;
constructor() { a = 0; b = false; }
export circuit x(v: Uint<64>): [] { assert(blockTimeGte(disclose(v)), \"condition\"); assert(disclose(v > a), \"condition\"); b = true; }`;
  // The actual library bound must be imported under a distinct alias so a local
  // same-name function cannot accidentally authenticate caller time.
  check(callerSuppliedTimeReview, namesake, 1, "pragma language_version >= 0.23; import { blockTimeGte as actualBound } from CompactStandardLibrary;\n");
});

test("development reviews remain opt-in without reserving unimplemented public IDs", () => {
  for (const rule of [callerSuppliedTimeReview, unassertedSecurityResult, witnessDerivedValueReview]) assert.equal(rule.defaultEnabled, false);
  for (const id of ["context-binding-review", "field-arithmetic-domain-review", "terminal-state-exclusivity-review"]) {
    withFiles({ "main.compact": "export circuit entry(): [] {}" }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [id] });
      assert.equal(result.status, "incomplete");
      assert.ok(result.diagnostics.some(d => /Unknown detector/i.test(d.message)));
    });
  }
});

// Excluded transfers must never be presented as a clean complete review.
test("development review reports unsupported loop transfers", () => {
  withFiles({ "main.compact": header + time('for (const i of 0..2) { b = true; }') }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [callerSuppliedTimeReview.id] });
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(issue => issue.code === "development-pattern-loop"));
  });
});

test("development review reports branch-budget exhaustion", () => {
  const branches = Array.from({ length: 10 }, (_, index) => `if (disclose(v == ${index})) { b = true; } else { b = false; }`).join("\n");
  withFiles({ "main.compact": header + time(branches + " b = true;") }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [callerSuppliedTimeReview.id] });
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(issue => issue.code === "development-pattern-budget"));
  });
});
