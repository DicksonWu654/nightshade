import assert from "node:assert/strict";
import test from "node:test";
import { PersistentTransitionCorpus, PERSISTENT_CORPUS_DEFAULTS, PERSISTENT_CORPUS_MAXIMA, auditPersistentCorpus, foldPersistentCorpus, validatePersistentCorpusBudgets, type PersistentCorpusSnapshot } from "./generative/persistent-corpus.js";
import { extractPersistentFeedback } from "./generative/persistent-feedback.js";
import { incompletePersistentResult, makePersistentArtifact, persistentBuildIdentity, runPersistentSequenceIsolated, type PersistentIdentity, type PersistentResult } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, validatePersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentObservation, type PersistentOperation, type PersistentSequence } from "./generative/persistent-model.js";

const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const sequence = (operations: PersistentOperation[] = [], seed = 17) => validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed, operations });
const empty = sequence(), accept = sequence([{ kind: "accept" }]), rejection = sequence([{ kind: "reject" }]);

/** Explicit synthetic schema/admission evidence, produced without runtime execution. */
function synthetic(model: PersistentSequence, hashPrefix = "synthetic-public"): PersistentObservation {
  const expected = expectedPersistentSequence(model);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`${hashPrefix}:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(model)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const checked = (model: PersistentSequence, wire = synthetic(model)) => checkPersistentObservation(model, wire, PERSISTENT_SOURCE_SHA256);
const bytes = (model = empty, result: PersistentResult = checked(model), expectedIdentity = identity, workerLimits = limits) => Buffer.from(JSON.stringify(makePersistentArtifact(model, expectedIdentity, workerLimits, result)));
const dataBytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const retainedData = (snapshot: PersistentCorpusSnapshot) => ({ features: snapshot.features, entries: snapshot.entries, compiledJavaScriptSha256: snapshot.compiledJavaScriptSha256 });
function capture(budgets = {}) { return new PersistentTransitionCorpus(identity, limits, budgets); }
function feedback(model: PersistentSequence) {
  const outcome = extractPersistentFeedback(model, checked(model)); assert.equal(outcome.status, "complete");
  if (outcome.status !== "complete") throw new Error("Expected synthetic passing feedback");
  return outcome.feedback;
}

function assertStopped(corpus: PersistentTransitionCorpus, diagnostic: string): void {
  const snapshot = corpus.snapshot();
  let invocations = 0;
  const hostile = new Proxy({}, { getPrototypeOf() { invocations++; return Object.prototype; }, ownKeys() { invocations++; return []; }, get() { invocations++; return undefined; } });
  const refused = corpus.consider(hostile);
  assert.equal(invocations, 0, "Stopped corpus inspected additional input");
  assert.deepEqual(refused, { schemaVersion: "nightshade-persistent-admission-1", ordinal: null, artifact: null, status: "incomplete", caseStatus: null, signature: null, feedbackSha256: null, admittedFeatureIds: [], diagnostic });
  assert.deepEqual(corpus.snapshot(), snapshot, "Repeated terminal refusals must not grow state");
}

test("synthetic empty constructor admission retains original bytes, exactly one feature and detached identities", () => {
  const expectedIdentity = structuredClone(identity), workerLimits = { ...limits }, budgets = { maxCases: 2 };
  const corpus = new PersistentTransitionCorpus(expectedIdentity, workerLimits, budgets);
  expectedIdentity.analyzerSourceSha256 = "0".repeat(64); workerLimits.timeoutMs = 1; budgets.maxCases = 1;
  const original = bytes(), first = corpus.consider(original);
  assert.equal(first.status, "retained"); assert.equal(first.caseStatus, "passed"); assert.equal(first.ordinal, 1);
  assert.deepEqual(first.artifact, { sha256: persistentDigest(original), bytes: original.length });
  assert.deepEqual(first.admittedFeatureIds, [persistentDigest(JSON.stringify(["initial", "zero"]))]);
  const snapshot = corpus.snapshot();
  assert.deepEqual(snapshot.identity, identity); assert.deepEqual(snapshot.workerLimits, limits);
  assert.equal(snapshot.budgets.maxCases, 2); assert.equal(snapshot.considered, 1); assert.equal(snapshot.evidenceBytes, original.length);
  assert.equal(snapshot.compiledJavaScriptSha256, "a".repeat(64)); assert.equal(snapshot.terminalDiagnostic, null);
  assert.deepEqual(snapshot.features, [{ id: first.admittedFeatureIds[0], descriptor: ["initial", "zero"] }]);
  assert.equal(snapshot.entries[0].ordinal, 1); assert.equal(snapshot.entries[0].feedbackSha256, first.feedbackSha256);
  assert.equal(snapshot.entries[0].sequenceSha256, persistentDigest(JSON.stringify(empty)));
  assert.equal(snapshot.entries[0].operationsSha256, persistentDigest("[]"));
  original.fill(0); first.admittedFeatureIds.length = 0; snapshot.features.length = 0; snapshot.entries[0].sequence.operations.push({ kind: "accept" });
  assert.equal(corpus.snapshot().features.length, 1); assert.deepEqual(corpus.snapshot().entries[0].sequence, empty);
});

test("duplicate, formatting-only, seed-only and hash-renamed evidence cannot manufacture novelty", () => {
  const corpus = capture(), original = bytes(accept);
  const seed = sequence(accept.operations, 99);
  const hashes = checked(accept, synthetic(accept, "different-public-bytes"));
  const artifacts = [original, original, Buffer.from(JSON.stringify(JSON.parse(original.toString()), null, 2) + "\n"), bytes(seed), bytes(accept, hashes)];
  const admissions = artifacts.map(artifact => corpus.consider(artifact));
  assert.deepEqual(admissions.map(row => row.status), ["retained", "redundant", "redundant", "redundant", "redundant"]);
  assert.notEqual(admissions[0].artifact!.sha256, admissions[2].artifact!.sha256);
  assert.notEqual(admissions[0].feedbackSha256, admissions[3].feedbackSha256, "Seed remains provenance even though novelty ignores it");
  assert.equal(corpus.snapshot().entries.length, 1);
  assert.equal(corpus.snapshot().evidenceBytes, artifacts.reduce((sum, artifact) => sum + artifact.length, 0));
  assert.deepEqual(auditPersistentCorpus(corpus.snapshot(), artifacts, admissions).snapshot, corpus.snapshot());
});

test("injective slot renaming is redundant while changed observed restoration history can be novel", () => {
  const first = sequence([{ kind: "accept" }, { kind: "save", slot: 3 }, { kind: "accept" }, { kind: "restore", slot: 3 }]);
  const renamed = sequence(first.operations.map(operation => "slot" in operation ? { ...operation, slot: 0 } : operation));
  const changed = sequence([{ kind: "accept" }, { kind: "save", slot: 3 }, { kind: "accept" }, { kind: "restore", slot: 0 }]);
  const corpus = capture();
  assert.equal(corpus.consider(bytes(first)).status, "retained");
  assert.equal(corpus.consider(bytes(renamed)).status, "redundant");
  const novel = corpus.consider(bytes(changed)); assert.equal(novel.status, "retained"); assert.ok(novel.admittedFeatureIds.length > 0);
  assert.equal(corpus.snapshot().entries.length, 2); assert.equal(corpus.snapshot().entries[1].ordinal, 3);
});

test("case and feature exhaustion is atomic, sticky and reconstructed from the triggering original case", () => {
  for (const budgets of [{ maxCases: 1 }, { maxFeatures: 1 }]) {
    const corpus = capture(budgets), initial = bytes(), duplicate = bytes(sequence([], 19)), novel = bytes(accept);
    const first = corpus.consider(initial); assert.equal(first.status, "retained");
    const second = corpus.consider(duplicate); assert.equal(second.status, "redundant", "Redundancy is allowed at retained capacity");
    const before = retainedData(corpus.snapshot()), third = corpus.consider(novel);
    assert.equal(third.status, "incomplete"); assert.equal(third.diagnostic, "persistent-corpus-budget");
    assert.equal(third.caseStatus, "passed"); assert.ok(third.feedbackSha256); assert.deepEqual(third.admittedFeatureIds, []);
    assert.deepEqual(retainedData(corpus.snapshot()), before);
    assertStopped(corpus, "persistent-corpus-budget");
    const reconstructed = auditPersistentCorpus(corpus.snapshot(), [initial, duplicate, novel], [first, second, third]);
    assert.equal(reconstructed.status, "incomplete"); assert.equal(reconstructed.snapshot.terminalDiagnostic, "persistent-corpus-budget");
  }
  const precise = capture({ maxFeatures: feedback(accept).features.length });
  assert.equal(precise.consider(bytes(accept)).status, "retained", "Exact feature capacity is permitted");
  const noPartial = capture({ maxFeatures: feedback(accept).features.length - 1 });
  assert.equal(noPartial.consider(bytes(accept)).status, "incomplete");
  assert.deepEqual(retainedData(noPartial.snapshot()), { features: [], entries: [], compiledJavaScriptSha256: null });
});

test("consideration and evidence ceilings stop before capture and never report a successful prefix", () => {
  const artifact = bytes();
  for (const budgets of [{ maxConsiderations: 2 }, { maxEvidenceBytes: artifact.length * 2 }]) {
    const corpus = capture(budgets), admissions = [corpus.consider(artifact), corpus.consider(artifact)];
    const before = corpus.snapshot(), final = corpus.consider(artifact); admissions.push(final);
    const diagnostic = "maxConsiderations" in budgets ? "persistent-corpus-consideration-budget" : "persistent-corpus-evidence-budget";
    assert.equal(final.status, "incomplete"); assert.equal(final.diagnostic, diagnostic); assert.equal(final.ordinal, null); assert.equal(final.artifact, null);
    assert.equal(corpus.snapshot().considered, before.considered); assert.equal(corpus.snapshot().evidenceBytes, before.evidenceBytes);
    assertStopped(corpus, diagnostic);
    assert.equal(auditPersistentCorpus(corpus.snapshot(), [artifact, artifact, artifact], admissions).status, "incomplete");
    assert.throws(() => auditPersistentCorpus(corpus.snapshot(), [artifact, artifact], admissions), /differ/);
    assert.throws(() => foldPersistentCorpus(identity, limits, budgets, [artifact, artifact, artifact, artifact]), /trailing/);
  }
  const tooSmall = capture({ maxEvidenceBytes: artifact.length - 1 });
  const decision = tooSmall.consider(artifact); assert.equal(decision.ordinal, null); assert.equal(decision.artifact, null); assert.equal(tooSmall.snapshot().considered, 0);
  const tooLarge = capture(); const capped = tooLarge.consider(new Uint8Array(1048577));
  assert.equal(capped.diagnostic, "persistent-corpus-evidence-budget"); assert.equal(capped.artifact, null); assert.equal(tooLarge.snapshot().evidenceBytes, 0);
});

test("strict budget controls reject unknown, accessor, hidden, sparse and noncanonical settings", () => {
  assert.deepEqual(validatePersistentCorpusBudgets(), PERSISTENT_CORPUS_DEFAULTS);
  assert.deepEqual(validatePersistentCorpusBudgets(PERSISTENT_CORPUS_MAXIMA), PERSISTENT_CORPUS_MAXIMA);
  for (const [key, maximum] of Object.entries(PERSISTENT_CORPUS_MAXIMA)) for (const value of [0, -0, -1, 1.5, NaN, Infinity, undefined, String(maximum), maximum + 1]) assert.throws(() => capture({ [key]: value }));
  for (const value of [null, [], { extra: true }, Object.create({ maxCases: 1 }), { [Symbol("unexpected")]: 1 }]) assert.throws(() => capture(value as never));
  const hidden = {}; Object.defineProperty(hidden, "maxCases", { value: 1 }); assert.throws(() => capture(hidden));
  let invocations = 0;
  const getter = {}; Object.defineProperty(getter, "maxCases", { enumerable: true, get() { invocations++; return 1; } });
  assert.throws(() => capture(getter)); assert.equal(invocations, 0, "Budget getter invoked");
  const identityGetter = { ...identity }; Object.defineProperty(identityGetter, "analyzerSourceSha256", { enumerable: true, get() { invocations++; return identity.analyzerSourceSha256; } });
  invocations = 0; assert.throws(() => new PersistentTransitionCorpus(identityGetter, limits)); assert.equal(invocations, 0, "Identity getter invoked");
  const limitsGetter = { ...limits }; Object.defineProperty(limitsGetter, "timeoutMs", { enumerable: true, get() { invocations++; return limits.timeoutMs; } });
  invocations = 0; assert.throws(() => new PersistentTransitionCorpus(identity, limitsGetter)); assert.equal(invocations, 0, "Worker-limit getter invoked");
});

test("invalid byte containers are not converted or invoked and oversized bytes are not parsed", () => {
  let invocations = 0;
  const decorated = bytes(); Object.defineProperty(decorated, "payload", { get() { invocations++; return undefined; } });
  const subclass = new (class CustomBytes extends Uint8Array {})();
  const hostile = { toString() { invocations++; return "{}"; }, valueOf() { invocations++; return "{}"; } };
  for (const input of [decorated, subclass, hostile, "{}", [], null]) {
    invocations = 0;
    const corpus = capture(), admission = corpus.consider(input);
    assert.equal(invocations, 0, "Byte input invoked an accessor or conversion");
    assert.equal(admission.status, "incomplete"); assert.equal(admission.diagnostic, "persistent-corpus-protocol"); assert.equal(admission.ordinal, null); assert.equal(admission.artifact, null);
    assert.equal(corpus.snapshot().considered, 0); assert.equal(corpus.snapshot().evidenceBytes, 0); assertStopped(corpus, "persistent-corpus-protocol");
  }
  const plainBytes = Uint8Array.from(bytes()); assert.equal(capture().consider(plainBytes).status, "retained");
});

test("malformed captured artifacts charge evidence but cannot admit content or bind compiled code", () => {
  const canonical = JSON.parse(bytes(accept).toString());
  const unknown = structuredClone(canonical); unknown.claimedFeatures = ["forged-edge"];
  const wrongResult = structuredClone(canonical); wrongResult.result.signature = "forged-pass";
  const forgedFeedback = structuredClone(canonical); forgedFeedback.result.feedback = feedback(accept);
  const missing = structuredClone(canonical); delete missing.result.observation;
  const wrongRow = structuredClone(canonical); wrongRow.result.observation.rows[0].index = 1;
  const negativeZero = Buffer.from(bytes(accept).toString().replace('"index":0', '"index":-0'));
  for (const original of [Buffer.from("{"), new Uint8Array([0xff]), dataBytes(unknown), dataBytes(wrongResult), dataBytes(forgedFeedback), dataBytes(missing), dataBytes(wrongRow), negativeZero]) {
    const corpus = capture(), decision = corpus.consider(original);
    assert.equal(decision.status, "incomplete"); assert.equal(decision.diagnostic, "persistent-corpus-protocol");
    assert.deepEqual(decision.artifact, { sha256: persistentDigest(original), bytes: original.length });
    assert.equal(corpus.snapshot().considered, 1); assert.equal(corpus.snapshot().evidenceBytes, original.length);
    assert.deepEqual(retainedData(corpus.snapshot()), { features: [], entries: [], compiledJavaScriptSha256: null });
    assert.equal(auditPersistentCorpus(corpus.snapshot(), [original], [decision]).status, "incomplete");
    assertStopped(corpus, "persistent-corpus-protocol");
  }
});

test("full build identity, source/runtime pins, saved limits and compiled JavaScript linkage are enforced", () => {
  for (const key of Object.keys(identity) as (keyof PersistentIdentity)[]) {
    const changed = { ...identity, [key]: key.endsWith("Sha256") ? "0".repeat(64) : key === "node" ? "v22.23.3" : `${identity[key]}-changed` };
    const artifact = JSON.parse(bytes().toString()); artifact.identity = changed;
    const corpus = capture(), decision = corpus.consider(dataBytes(artifact));
    assert.equal(decision.status, "incomplete", key);
    assert.equal(decision.diagnostic, ["persistentFixtureSha256", "runtimeLockSha256", "semanticProfile"].includes(key) ? "persistent-corpus-protocol" : "persistent-corpus-identity", key);
    assert.deepEqual(retainedData(corpus.snapshot()), { features: [], entries: [], compiledJavaScriptSha256: null });
  }
  for (const change of [{ timeoutMs: 999 }, { heapMiB: 63 }, { maxOutputBytes: 16383 }]) {
    const corpus = capture(), decision = corpus.consider(bytes(empty, checked(empty), identity, { ...limits, ...change }));
    assert.equal(decision.diagnostic, "persistent-corpus-identity");
  }
  const corpus = capture(); corpus.consider(bytes()); const before = retainedData(corpus.snapshot());
  const wire = synthetic(accept); wire.compiledJavaScriptSha256 = "b".repeat(64);
  const drift = corpus.consider(bytes(accept, checked(accept, wire)));
  assert.equal(drift.status, "incomplete"); assert.equal(drift.diagnostic, "persistent-corpus-compiled-build-drift");
  assert.deepEqual(retainedData(corpus.snapshot()), before); assertStopped(corpus, "persistent-corpus-compiled-build-drift");
});

test("qualified synthetic property failures keep their signature and never become parents or novelty", () => {
  for (const mutate of [
    (wire: PersistentObservation) => { wire.rows[0].after.next = "8"; },
    (wire: PersistentObservation) => { wire.rows[0].witnesses[0] = "9"; },
    (wire: PersistentObservation) => { wire.rows[0].slots[0].count = "1"; },
    (wire: PersistentObservation) => { wire.rows[0].after.publicSha256 = "b".repeat(64); },
    (wire: PersistentObservation) => { wire.rows[0].outcome = "evaluation-success"; wire.rows[0].error = null; },
  ]) {
    const wire = synthetic(rejection); mutate(wire); const result = checked(rejection, wire); assert.equal(result.status, "failed");
    const original = bytes(rejection, result), corpus = capture(), decision = corpus.consider(original);
    assert.equal(decision.status, "property-failed"); assert.equal(decision.caseStatus, "failed"); assert.equal(decision.signature, result.signature);
    assert.equal(decision.feedbackSha256, null); assert.deepEqual(decision.admittedFeatureIds, []);
    assert.deepEqual(retainedData(corpus.snapshot()), { features: [], entries: [], compiledJavaScriptSha256: null });
    assert.equal(auditPersistentCorpus(corpus.snapshot(), [original], [decision]).status, "property-failed");
    assertStopped(corpus, "persistent-model-disagreement");
  }
  const qualifiedReject = capture().consider(bytes(rejection)); assert.equal(qualifiedReject.status, "retained"); assert.equal(qualifiedReject.caseStatus, "passed");
});

test("incomplete runtime outcomes retain diagnostic identity and cannot supply predicted novelty", () => {
  for (const diagnostic of ["worker-timeout", "worker-output-budget", "worker-interrupted", "persistent-unqualified-rejection", "persistent-observation-budget", "persistent-input-identity"]) {
    const original = bytes(accept, incompletePersistentResult(diagnostic, "Synthetic incomplete evidence; no runtime execution claimed"));
    const corpus = capture(), decision = corpus.consider(original);
    assert.equal(decision.status, "incomplete"); assert.equal(decision.caseStatus, "incomplete"); assert.equal(decision.diagnostic, diagnostic); assert.equal(decision.signature, diagnostic);
    assert.equal(decision.feedbackSha256, null); assert.deepEqual(decision.admittedFeatureIds, []); assert.equal(corpus.snapshot().features.length, 0);
    assert.equal(auditPersistentCorpus(corpus.snapshot(), [original], [decision]).status, "incomplete"); assertStopped(corpus, diagnostic);
  }
  const wire = synthetic(rejection); wire.rows[0].error!.message = "Different error is not qualified";
  const result = checked(rejection, wire); assert.equal(result.status, "incomplete"); assert.equal(result.diagnostic, "persistent-unqualified-rejection");
  assert.equal(capture().consider(bytes(rejection, result)).diagnostic, "persistent-unqualified-rejection");
});

test("ordered original-artifact audit rederives all snapshot and admission fields", () => {
  const artifacts = [bytes(), bytes(accept), bytes(rejection)], folded = foldPersistentCorpus(identity, limits, {}, artifacts);
  assert.equal(folded.status, "complete"); assert.equal(folded.scope, "offline-evidence-consistency-only");
  assert.deepEqual(folded.admissions.map(row => row.status), ["retained", "retained", "retained"]);
  assert.deepEqual(auditPersistentCorpus(folded.snapshot, artifacts, folded.admissions), folded);
  assert.throws(() => auditPersistentCorpus(folded.snapshot, artifacts.slice(0, 2), folded.admissions));
  assert.throws(() => auditPersistentCorpus(folded.snapshot, [artifacts[1], artifacts[0], artifacts[2]], folded.admissions));
  for (const change of [
    (snapshot: any) => { snapshot.schemaVersion = "nightshade-runtime-transition-corpus-1"; },
    (snapshot: any) => { snapshot.considered--; },
    (snapshot: any) => { snapshot.evidenceBytes++; },
    (snapshot: any) => { snapshot.compiledJavaScriptSha256 = "b".repeat(64); },
    (snapshot: any) => { snapshot.terminalDiagnostic = "persistent-corpus-budget"; },
    (snapshot: any) => { snapshot.features[0].descriptor[0] = "execution-edge"; },
    (snapshot: any) => { snapshot.features[0].id = "0".repeat(64); },
    (snapshot: any) => { snapshot.features.reverse(); },
    (snapshot: any) => { snapshot.entries[0].sequence.seed++; },
    (snapshot: any) => { snapshot.entries[1].admittedFeatureIds.length = 0; },
    (snapshot: any) => { snapshot.entries[1].featureIds.push("0".repeat(64)); },
    (snapshot: any) => { snapshot.entries[0].artifactBytes++; },
    (snapshot: any) => { snapshot.entries[0].feedbackSha256 = "f".repeat(64); },
    (snapshot: any) => { snapshot.entries[0].operationsSha256 = "f".repeat(64); },
    (snapshot: any) => { snapshot.entries[0].observationSha256 = "f".repeat(64); },
    (snapshot: any) => { snapshot.entries[0].ordinal = 2; },
  ]) { const snapshot = structuredClone(folded.snapshot); change(snapshot); assert.throws(() => auditPersistentCorpus(snapshot, artifacts, folded.admissions)); }
  for (const change of [
    (admissions: any[]) => { admissions[0].status = "redundant"; },
    (admissions: any[]) => { admissions[0].admittedFeatureIds = []; },
    (admissions: any[]) => { admissions[0].artifact.sha256 = "0".repeat(64); },
    (admissions: any[]) => { admissions[0].caseStatus = "failed"; },
    (admissions: any[]) => { admissions[0].feedbackSha256 = null; },
    (admissions: any[]) => { admissions[0].diagnostic = "persistent-corpus-budget"; },
    (admissions: any[]) => { admissions[0].signature = "different"; },
    (admissions: any[]) => { admissions[0].ordinal = null; },
  ]) { const admissions = structuredClone(folded.admissions); change(admissions); assert.throws(() => auditPersistentCorpus(folded.snapshot, artifacts, admissions)); }
});

test("audit rejects hostile saved descendants and evidence arrays without invoking getters", () => {
  const artifacts = [bytes()], folded = foldPersistentCorpus(identity, limits, {}, artifacts);
  let invocations = 0;
  for (const mutate of [
    (snapshot: any) => { Object.defineProperty(snapshot, "features", { enumerable: true, get() { invocations++; return []; } }); },
    (snapshot: any) => { Object.defineProperty(snapshot.entries[0], "sequence", { enumerable: true, get() { invocations++; return empty; } }); },
    (snapshot: any) => { Object.defineProperty(snapshot, "considered", { value: 1, enumerable: false }); },
    (snapshot: any) => { snapshot[Symbol("extra")] = 0; },
    (snapshot: any) => { snapshot.features.extra = true; },
    (snapshot: any) => { delete snapshot.entries[0]; },
    (snapshot: any) => { snapshot.evidenceBytes = NaN; },
    (snapshot: any) => { snapshot.entries[0].ordinal = -0; },
    (snapshot: any) => { Object.setPrototypeOf(snapshot.entries[0], { inherited: true }); },
  ]) {
    invocations = 0;
    const snapshot = structuredClone(folded.snapshot); mutate(snapshot);
    assert.throws(() => auditPersistentCorpus(snapshot, artifacts, folded.admissions));
    assert.equal(invocations, 0, "Saved snapshot accessor invoked");
  }
  const admissionGetters = structuredClone(folded.admissions);
  Object.defineProperty(admissionGetters[0].artifact, "sha256", { enumerable: true, get() { invocations++; return persistentDigest(artifacts[0]); } });
  invocations = 0; assert.throws(() => auditPersistentCorpus(folded.snapshot, artifacts, admissionGetters));
  assert.equal(invocations, 0, "Saved admission descendant accessor invoked");
  const topAdmissionGetter = structuredClone(folded.admissions);
  Object.defineProperty(topAdmissionGetter[0], "feedbackSha256", { enumerable: true, get() { invocations++; return folded.admissions[0].feedbackSha256; } });
  invocations = 0; assert.throws(() => auditPersistentCorpus(folded.snapshot, artifacts, topAdmissionGetter));
  assert.equal(invocations, 0, "Saved admission accessor invoked");
  const accessor: unknown[] = [null]; Object.defineProperty(accessor, 0, { enumerable: true, get() { invocations++; return artifacts[0]; } });
  const extra = [bytes()] as unknown[] & { extra?: number }; extra.extra = 1;
  for (const inputs of [accessor, Array(1), extra, Array(258), Object.create([])]) {
    invocations = 0; assert.throws(() => foldPersistentCorpus(identity, limits, {}, inputs));
    assert.equal(invocations, 0, "Original evidence array accessor invoked");
  }
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
const lifecycle = sequence([{ kind: "restore", slot: 3 }, { kind: "accept" }, { kind: "reject" }, { kind: "accept" }, { kind: "save", slot: 0 },
  { kind: "accept" }, { kind: "save", slot: 1 }, { kind: "restore", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 3 },
  { kind: "restore", slot: 3 }, { kind: "save", slot: 0 }, { kind: "restore", slot: 1 }, { kind: "inspect" }]);

test("measured fixed-worker lifecycle admits complete feedback and reconstructs exact original evidence", qualified, async () => {
  assert.ok(process.env.COMPACTC_TEST, "Runtime qualification requires its pinned compiler companion");
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!, actualIdentity = persistentBuildIdentity(compiler, runtime);
  const measured = await runPersistentSequenceIsolated(lifecycle, compiler, runtime); assert.equal(measured.status, "passed");
  const original = dataBytes(makePersistentArtifact(lifecycle, actualIdentity, PERSISTENT_LIMITS, measured));
  const seed = sequence(lifecycle.operations, lifecycle.seed + 1), repeated = await runPersistentSequenceIsolated(seed, compiler, runtime); assert.equal(repeated.status, "passed");
  assert.deepEqual(repeated.observation.rows, measured.observation.rows);
  const duplicate = dataBytes(makePersistentArtifact(seed, actualIdentity, PERSISTENT_LIMITS, repeated));
  const corpus = new PersistentTransitionCorpus(actualIdentity, PERSISTENT_LIMITS), admissions = [corpus.consider(original), corpus.consider(duplicate)];
  assert.deepEqual(admissions.map(row => row.status), ["retained", "redundant"]);
  const checkedFeedback = extractPersistentFeedback(lifecycle, measured); assert.equal(checkedFeedback.status, "complete");
  if (checkedFeedback.status !== "complete") throw new Error("No measured feedback");
  assert.deepEqual(checkedFeedback.feedback.counts.operationRows, 14);
  assert.equal(checkedFeedback.feedback.counts.circuitEvaluations, 6); assert.equal(checkedFeedback.feedback.counts.adapterOperations, 8);
  const descriptors = checkedFeedback.feedback.features.map(feature => JSON.stringify(feature.descriptor));
  for (const descriptor of [
    ["initial", "zero"],
    ["operation-outcome", "circuit", "reject", "evaluation-rejection"],
    ["snapshot-transition", "adapter", "restore", "negative-one", "negative-one", false],
    ["restore", false, "unavailable", "equal", "equal", true, true],
    ["restore", true, true, "greater", "greater", false, false],
  ]) assert.ok(descriptors.includes(JSON.stringify(descriptor)), JSON.stringify(descriptor));
  assert.deepEqual(auditPersistentCorpus(corpus.snapshot(), [original, duplicate], admissions).snapshot, corpus.snapshot());
  // Tampered copies of measured evidence test admission refusal, not discovered runtime defects.
  const tampered = structuredClone(measured.observation); tampered.rows[2].witnesses[0] = "999";
  const failed = checkPersistentObservation(lifecycle, tampered, PERSISTENT_SOURCE_SHA256); assert.equal(failed.status, "failed");
  const corrupt = dataBytes(makePersistentArtifact(lifecycle, actualIdentity, PERSISTENT_LIMITS, failed));
  const refusal = corpus.consider(corrupt); assert.equal(refusal.status, "property-failed"); assert.equal(corpus.snapshot().entries.length, 1);
  assert.equal(auditPersistentCorpus(corpus.snapshot(), [original, duplicate, corrupt], [...admissions, refusal]).status, "property-failed");
});

test("[timing] measured supervised timeout contributes no corpus features and remains incomplete during reconstruction", qualified, async () => {
  assert.ok(process.env.COMPACTC_TEST, "Runtime qualification requires its pinned compiler companion");
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!, actualIdentity = persistentBuildIdentity(compiler, runtime);
  const workerLimits = { ...PERSISTENT_LIMITS, timeoutMs: 1 };
  const result = await runPersistentSequenceIsolated(lifecycle, compiler, runtime, workerLimits);
  assert.equal(result.status, "incomplete"); assert.equal(result.diagnostic, "worker-timeout");
  const original = dataBytes(makePersistentArtifact(lifecycle, actualIdentity, workerLimits, result));
  const corpus = new PersistentTransitionCorpus(actualIdentity, workerLimits), admission = corpus.consider(original);
  assert.equal(admission.diagnostic, "worker-timeout"); assert.equal(admission.caseStatus, "incomplete"); assert.equal(admission.feedbackSha256, null);
  assert.equal(corpus.snapshot().features.length, 0); assert.equal(corpus.snapshot().entries.length, 0);
  assert.equal(auditPersistentCorpus(corpus.snapshot(), [original], [admission]).status, "incomplete");
});
