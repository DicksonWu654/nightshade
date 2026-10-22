import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Program } from "../semantic/index.js";
import { buildAnalysisInventory } from "../analysis/inventory.js";
import { semanticProfile } from "../semantic/profile.js";
import { Dataflow } from "../dataflow/index.js";
import { predicateEvidence, trustedPreimageSources } from "../dataflow/predicates.js";
import { AnalysisError, type Diagnostic, type Expr, type Span, type Statement } from "../model.js";
import { scanFile, type ScanOptions, type ScanResult } from "../index.js";
import { runNodeModule, WorkerFailure, type ExecutionLimits } from "../runtime/process.js";
import { compactReviewDiagnostics, relativeReviewBrief, reviewMarkdown } from "./review-presentation.js";

export type ReviewOptions = Pick<ScanOptions, "compilerVersion" | "zkirVersion" | "searchPaths" | "sourceRoot" | "maxSteps" | "maxPaths" | "maxValues">;
interface Site { location: Span; expression: string; owner: string; sources?: { kind: string; name: string }[] }
export interface ReviewDiagnostic extends Diagnostic { count?: number; locations?: Span[] }
interface WriteSite extends Site { field: string; value: string; guarded: boolean }
export interface ReviewCircuit {
  id: string; name: string; location: Span; kind: string;
  arguments: { name: string; type: string; location: Span; control: string }[];
  witnesses: { id: string; name: string; location: Span }[];
  reads: string[]; writes: string[]; calls: string[];
  assertions: Site[]; disclosures: Site[]; timeUsage: Site[]; valueMovement: Site[]; writeSites: WriteSite[];
  timeGates: Site[]; markerWritesWithoutGuard: WriteSite[];
  publicSinks: { history: number; kind: string; name: string; location: Span; privateSources: string[]; ledgerSources: string[] }[];
  historyStatus: "complete" | "incomplete"; histories: number;
  authorization: { strength: string; scope: string; histories: { history: number; constraints: { location: Span; truth: boolean; writesBefore: number; operationsBefore: number }[]; privatePreimages: string[] }[] };
  findings: ScanResult["findings"];
}
export interface ReviewQuestion {
  id: string; rank: number; score: number; signals: string[];
  priority: "high" | "medium" | "low"; kind: string; circuitIds: string[]; locations: Span[]; question: string; basis: string;
}
export interface ReviewSummary { status: "complete" | "incomplete"; circuitCount: number; findingCount: number; questionCount: number; visibleQuestions: number; collapsedQuestions: number; diagnosticGroups: number; topQuestions: { rank: number; priority: string; kind: string; question: string; circuitIds: string[] }[] }
export interface ReviewBrief {
  schemaVersion: "nightshade-review-1"; status: "complete" | "incomplete"; root: string;
  semanticProfile?: string; scope: string;
  identity: { toolVersion: string; grammarBuild?: string; sources: { file: string; sha256: string }[]; budgets: { maxSteps: number; maxPaths: number; maxValues: number } };
  coverage: { scan: ScanResult["coverage"] | null; inventory: string; histories: string; diagnostics: ReviewDiagnostic[] };
  circuits: ReviewCircuit[];
  stateMachine: { scope: string; fields: { id: string; name: string; type: string; readers: string[]; writers: string[]; marker: string; assignments: WriteSite[] }[] };
  findings: ScanResult["findings"]; questions: ReviewQuestion[]; questionSummary: { visible: number; collapsed: number; generated: number };
  summary: ReviewSummary; pathFormat: "absolute" | "repository-relative";
  explorer: { status: "not-run" | "attached-source-unverified"; replays: { id?: string; circuit: string; status: string; transition: boolean }[]; reason: string; artifactSha256?: string; artifactPath?: string };
  limitations: string[];
}
const at = (file: string): Span => ({ file: resolve(file), start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 });
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
function empty(root: string, options: ReviewOptions): ReviewBrief {
  return { schemaVersion: "nightshade-review-1", root: resolve(root), status: "incomplete",
    scope: "Conservative resolved source relations and separate modeled successful histories. A row points to code for review; it does not detect or verify a vulnerability.",
    identity: { toolVersion: "0.1.1", sources: [], budgets: { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 } },
    coverage: { scan: null, inventory: "unavailable", histories: "unavailable", diagnostics: [] }, circuits: [],
    stateMachine: { scope: "May-read/write graph and source assignment sketch; marker candidates are heuristics, not proven terminal states or one-time actions.", fields: [] },
    findings: [], questions: [], questionSummary: { visible: 0, collapsed: 0, generated: 0 },
    summary: { status: "incomplete", circuitCount: 0, findingCount: 0, questionCount: 0, visibleQuestions: 0, collapsedQuestions: 0, diagnosticGroups: 0, topQuestions: [] },
    pathFormat: "absolute", explorer: { status: "not-run", replays: [], reason: "This command does not execute contracts or models. Explorer replay collection is a separate opt-in workflow." },
    limitations: ["Source relations include syntactically reachable helpers and may include infeasible routes.", "Observed checks are not proof of authentication, dominance, secret possession, transaction feasibility or deployment impact.", "Disclosure permission is not itself a public sink; disclosures below are source uses.", "Marker names and literal assignments only suggest states; no cross-transaction reachability or liveness is proven.", "No model is called. No runtime replay is inferred from a static fact."] };
}
function present(report: ReviewBrief, portable = true): ReviewBrief {
  report.coverage.diagnostics = compactReviewDiagnostics(report.coverage.diagnostics);
  report.questionSummary = { visible: Math.min(10, report.questions.length), collapsed: Math.max(0, report.questions.length - 10), generated: report.questions.length };
  report.summary = { status: report.status, circuitCount: report.circuits.length, findingCount: report.findings.length,
    questionCount: report.questions.length, visibleQuestions: report.questionSummary.visible, collapsedQuestions: report.questionSummary.collapsed,
    diagnosticGroups: report.coverage.diagnostics.length, topQuestions: report.questions.slice(0, 5).map(q => ({ rank: q.rank, priority: q.priority, kind: q.kind, question: q.question, circuitIds: q.circuitIds })) };
  return portable ? relativeReviewBrief(report) : report;
}

/** Builds a reviewer map from the owned model; grammar details stay in the parser. */
export function reviewFile(file: string, options: ReviewOptions = {}): ReviewBrief {
  const report = empty(file, options);
  try {
    for (const value of [options.maxSteps, options.maxPaths, options.maxValues])
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) throw new Error("Analysis budgets must be positive safe integers");
    const program = new Program(resolve(file), options.searchPaths, options.sourceRoot, undefined, options.zkirVersion, options.compilerVersion);
    const scan = scanFile(file, { ...options, profile: "audit" });
    report.findings = scan.findings; report.coverage.scan = scan.coverage;
    report.coverage.diagnostics.push(...scan.diagnostics); report.identity.grammarBuild = scan.grammarBuild;
    report.root = program.rootSource.path; report.semanticProfile = program.semanticProfile;
    report.identity.sources = [...program.files].map(([path, source]) => ({ file: path, sha256: hash(source.text) })).sort((a, b) => a.file.localeCompare(b.file));
    const inventory = buildAnalysisInventory(program);
    report.coverage.inventory = inventory.status;
    report.coverage.diagnostics.push(...inventory.gaps.map(gap => ({ code: gap.code, message: gap.message, location: gap.location })));
    const facts = new Dataflow(program, options.maxSteps, options.maxPaths, options.maxValues, "instructions", true, true, "equivalent-states", false, true, "all").analyze();
    report.coverage.diagnostics.push(...facts.diagnostics);
    report.coverage.histories = facts.diagnostics.length || program.entries.some(id => !facts.completedEntries.includes(id)) ? "incomplete" : "complete";
    const functions = new Map(inventory.functions.map(fn => [fn.id, fn]));
    let work = 0;
    const charge = (depth = 0) => { if (++work > 200000 || depth > 128) throw new AnalysisError({ code: "review-budget", message: "Review extraction exceeded its bounded work/depth; map is incomplete", location: at(file) }); };
    const sourceBytes = new Map([...program.files].map(([path, source]) => [path, Buffer.from(source.text)]));
    const excerpt = (span: Span) => (sourceBytes.get(span.file) ?? Buffer.alloc(0)).subarray(span.start, span.end).toString("utf8").replace(/\s+/g, " ").slice(0, 400);
    for (const entry of program.entries) {
      const fn = program.functions.get(entry)!;
      const closure = new Set<string>(), pending = [entry];
      while (pending.length) {
        charge(); const id = pending.pop()!; if (closure.has(id)) continue; closure.add(id);
        for (const call of program.functions.get(id)?.calls ?? []) { charge(); pending.push(call); }
      }
      const row: ReviewCircuit = { id: entry, name: fn.symbol.name, kind: fn.symbol.kind, location: fn.declaration.span,
        arguments: fn.declaration.parameters.map(p => ({ name: p.name, type: p.type, location: p.span, control: fn.symbol.kind === "constructor" ? "deployment-input" : "caller-controlled-input" })),
        witnesses: [...closure].flatMap(id => { const s = program.symbols.get(id); return s?.kind === "witness" ? [{ id, name: s.name, location: s.span }] : []; }),
        reads: [...fn.readsState].sort(), writes: [...fn.writesState].sort(), calls: [...closure].filter(id => id !== entry).sort(),
        assertions: [], disclosures: [], timeUsage: [], valueMovement: [], writeSites: [], timeGates: [], markerWritesWithoutGuard: [], publicSinks: [],
        historyStatus: facts.completedEntries.includes(entry) ? "complete" : "incomplete", histories: 0,
        authorization: { strength: "unavailable", scope: "Per-history observed constraints, not universal authorization. Completed helper calls and state checks alone do not authenticate a caller.", histories: [] }, findings: [] };
      const sourceKinds = (expr: Expr): { kind: string; name: string }[] => {
        const found: { kind: string; name: string }[] = [];
        const symbol = expr.symbol && program.symbols.get(expr.symbol);
        if (symbol && ["witness", "parameter", "ledger"].includes(symbol.kind)) found.push({ kind: symbol.kind, name: symbol.name });
        for (const arg of expr.args) found.push(...sourceKinds(arg));
        if (expr.body) { const walkSources = (statement: Statement): void => {
          if (statement.kind === "block" || statement.kind === "bindings") statement.body.forEach(walkSources);
          else if (statement.kind === "if") { sourceKinds(statement.condition); walkSources(statement.then); if (statement.otherwise) walkSources(statement.otherwise); }
          else if (statement.kind === "for") walkSources(statement.body); else sourceKinds(statement.expr);
        }; walkSources(expr.body); }
        return found;
      };
      const visit = (expr: Expr, owner: string, depth: number, guardDepth = 0): void => {
        charge(depth);
        const site = { location: expr.span, expression: excerpt(expr.span), owner, sources: sourceKinds(expr) };
        const symbol = expr.symbol && program.symbols.get(expr.symbol);
        if (expr.kind === "assert") row.assertions.push(site);
        if (expr.kind === "disclose") row.disclosures.push(site);
        if (expr.kind === "call" && symbol && /^standard-library::blockTime/.test(symbol.id)) row.timeUsage.push(site);
        if (expr.kind === "ref" && symbol && ["parameter", "ledger", "witness"].includes(symbol.kind) && /time|epoch|deadline|expiry|expires|eta|now/i.test(symbol.name)) row.timeUsage.push(site);
        if (expr.kind === "call" && symbol && /^standard-library::(?:send|receive|mint|createZswap|burn|mergeCoin)/.test(symbol.id)) row.valueMovement.push(site);
        if (expr.kind === "assign" && expr.args[0]) {
          const target = expr.args[0], field = target.ledgerRoot ?? target.symbol;
          if (field && program.symbols.get(field)?.kind === "ledger") {
            const guarded = guardDepth > 0 || row.assertions.some(a => a.owner === owner && a.location.file === expr.span.file && a.location.start < expr.span.start);
            const write = { ...site, field, value: excerpt(expr.args[1]?.span ?? expr.span), guarded };
            row.writeSites.push(write);
            if (!guarded && /state|phase|status|terminal|done|claimed|consumed|used|initialized|confirmed|settled|released/i.test(program.symbols.get(field)?.name ?? "")) row.markerWritesWithoutGuard.push(write);
          }
        }
        for (const arg of expr.args) visit(arg, owner, depth + 1, guardDepth);
        if (expr.body) walk(expr.body, owner, depth + 1, guardDepth);
      };
      const walk = (statement: Statement, owner: string, depth: number, guardDepth = 0): void => {
        charge(depth);
        if (statement.kind === "block" || statement.kind === "bindings") for (const child of statement.body) walk(child, owner, depth + 1, guardDepth);
        else if (statement.kind === "if") { visit(statement.condition, owner, depth + 1, guardDepth); walk(statement.then, owner, depth + 1, guardDepth + 1); if (statement.otherwise) walk(statement.otherwise, owner, depth + 1, guardDepth + 1); }
        else if (statement.kind === "for") { if (statement.sequence) visit(statement.sequence, owner, depth + 1, guardDepth); walk(statement.body, owner, depth + 1, guardDepth + 1); }
        else visit(statement.expr, owner, depth + 1, guardDepth);
      };
      for (const id of closure) {
        charge(); const body = program.functions.get(id)?.declaration.body;
        // Library internals are summarized by canonical operation sites above.
        if (body && !id.startsWith("standard-library::")) walk(body, id, 0);
      }
      const paths = facts.paths.filter(p => p.entry === entry); row.histories = paths.length;
      for (const [history, path] of paths.entries()) {
        charge(); const evidence = predicateEvidence(path, Math.max(1, 200000 - work)); work += evidence.work;
        if (!evidence.complete) throw new AnalysisError({ code: "review-predicate-budget", message: "Review predicate decoding is incomplete", location: row.location });
        for (const sink of path.sinks) {
          charge(); row.publicSinks.push({ history, kind: sink.kind, name: sink.name, location: sink.location,
            privateSources: [...new Set(sink.value.flows.map(f => f.source.name))], ledgerSources: [...sink.value.ledger].sort() });
        }
        row.authorization.histories.push({ history,
          constraints: (path.predicates ?? []).map(p => { charge(); return { location: p.location, truth: p.truth, writesBefore: p.writesBefore, operationsBefore: p.operationsBefore }; }),
          privatePreimages: [...new Set(evidence.equalities.flatMap(e => trustedPreimageSources(e.equality)).map(s => s.name))] });
      }
      row.authorization.strength = row.historyStatus !== "complete" ? "unavailable-for-universal-claims"
        : row.authorization.histories.some(h => h.privatePreimages.length) ? "private-preimage-observed-on-listed-histories"
          : row.assertions.length ? "checks-observed-authentication-unclassified" : "no-check-observed-in-source";
      row.timeGates = row.assertions.filter(a => /(?:time|timestamp|epoch|deadline|expiry|expires|eta|now)/i.test(a.expression) && /(?:>=|<=|>|<|==)/.test(a.expression));
      row.findings = report.findings.filter(f => f.metadata.entry === row.name || f.callPath[0] === row.name
        || f.location.file === row.location.file && f.location.start >= row.location.start && f.location.end <= row.location.end);
      report.circuits.push(row);
      if (!functions.has(entry)) throw new Error("Inventory is missing a review entry");
    }
    const addQuestion = (kind: string, priority: ReviewQuestion["priority"], rows: ReviewCircuit[], locations: Span[], question: string, basis: string, score: number, signals: string[]) => {
      charge(); const ids = rows.map(r => r.id);
      // IDs use owned semantic/path coordinates; the report retains real paths.
      report.questions.push({ id: hash(JSON.stringify([program.meteringPath(report.root), kind, ids.map(program.meteringIdentity),
        locations.map(location => ({ ...location, file: program.meteringPath(location.file) })), question, basis])).slice(0, 20), rank: 0, score, signals, kind, priority, circuitIds: ids, locations, question, basis });
    };
    for (const row of report.circuits) {
      if (row.kind === "constructor") continue;
      if (row.valueMovement.length) {
        const noAuth = row.authorization.strength === "no-check-observed-in-source";
        addQuestion("value-authorization", "high", [row], row.valueMovement.map(x => x.location),
          `Who may invoke ${row.name}'s value operations, and can the observed checks be bypassed or satisfied with public/witness data?`, row.authorization.strength,
          (noAuth ? 100 : row.authorization.strength.startsWith("private") ? 58 : 72) + (row.name.toLowerCase().includes("mint") ? 12 : 0),
          [noAuth ? "no authorization evidence observed" : "authorization evidence is unclassified", row.name.toLowerCase().includes("mint") ? "mint operation" : "value movement"]);
      }
      if (row.timeUsage.length) {
        const gate = row.timeGates.length > 0;
        addQuestion("time-binding", "high", [row], (gate ? row.timeGates : row.timeUsage).map(x => x.location),
          gate ? `Is ${row.name}'s caller-supplied time actually bounded by protocol time at this gate, and can a future or stale value pass?` : `Where ${row.name} stores or consumes a caller time, is it bound to protocol time before a delayed effect?`,
          gate ? "Caller time is compared in an assertion gate." : "A time-like value is used without an observed comparison gate.", gate ? 92 : 38, [gate ? "caller time compared against gate" : "time value stored or consumed"]);
      }
      if (row.disclosures.length) {
        const witness = row.disclosures.some(x => x.sources?.some(s => s.kind === "witness"));
        addQuestion("privacy", "medium", [row], row.disclosures.map(x => x.location),
          witness ? `Do ${row.name}'s disclosures reveal witness-derived secrets or secret-dependent values beyond the protocol's privacy promises?` : `Do ${row.name}'s disclosures expose public identifiers, amounts or recipients beyond the protocol's privacy promises?`,
          witness ? "Disclosure expression depends on a witness source." : "Disclosure source is not witness-derived in the owned model.", witness ? 78 : 42, [witness ? "witness-derived disclosure" : "public or non-witness disclosure"]);
      }
      const markerWrites = row.writeSites.filter(w => /state|phase|status|terminal|done|claimed|consumed|used|initialized|confirmed|settled|released/i.test(w.field));
      const lifecycleName = /propose|initial|deliver|dispute|resolve|eta|release|claim|settle/i.test(row.name);
      if (markerWrites.length || (row.writes.length && lifecycleName) || row.arguments.some(a => /Uint|Field|Counter/i.test(a.type))) {
        const unguarded = row.markerWritesWithoutGuard.length > 0;
        const initialization = /propose|initial/i.test(row.name);
        const liveness = /deliver|dispute|resolve|eta/i.test(row.name);
        const boundary = row.arguments.some(a => /Uint|Field|Counter/i.test(a.type));
        const words = [initialization ? "be initialized by an unintended caller" : "be called repeatedly or race a competing transition", liveness ? "strand value when parties are unavailable or time limits expire" : "violate terminal or one-time behavior", boundary ? "mishandle zero or boundary inputs" : "accept an unintended caller"].join(", ");
        addQuestion("state-lifecycle", "medium", [row], [row.location, ...row.writeSites.map(x => x.location)],
          `Can ${row.name} ${words}, or enter a state with no authorized exit?`,
          unguarded ? "A marker-like field is written without a preceding guard." : "A state, lifecycle, or caller-controlled numeric transition is present.", unguarded ? 84 : (liveness || initialization ? 62 : 48), [unguarded ? "one-time marker write lacks guard" : "lifecycle write", liveness ? "expiry or recovery transition" : initialization ? "initialization transition" : boundary ? "numeric boundary input" : "state transition"]);
      }
      if (row.historyStatus !== "complete") addQuestion("coverage-gap", "high", [row], [row.location], `Review ${row.name} directly: successful-history analysis is incomplete.`, "No absence or universal guard inference is available.", 30, ["incomplete history coverage"]);
    }
    for (const ledger of inventory.ledgers) {
      charge();
      const readers = report.circuits.filter(r => r.reads.includes(ledger.id)), writers = report.circuits.filter(r => r.writes.includes(ledger.id));
      const marker = /state|phase|status|terminal|done|claimed|consumed|used|initialized|confirmed|settled|released/i.test(ledger.name)
        ? "terminal-or-one-time-candidate (name heuristic)" : "unclassified";
      report.stateMachine.fields.push({ id: ledger.id, name: ledger.name, type: ledger.type, readers: readers.map(r => r.id), writers: writers.map(r => r.id), marker,
        assignments: writers.flatMap(r => r.writeSites.filter(w => w.field === ledger.id)) });
      if (marker !== "unclassified" && writers.length) {
        const competingStateFields = inventory.ledgers.filter(candidate => candidate.id !== ledger.id && /state|phase|status|terminal|done|claimed|consumed|used|initialized|confirmed|settled|released/i.test(candidate.name));
        const related = report.circuits.filter(r => readers.includes(r) || writers.includes(r) || competingStateFields.some(candidate => r.writes.includes(candidate.id)));
        const unguarded = related.some(r => r.markerWritesWithoutGuard.some(w => w.field === ledger.id));
        const competition = related.length >= 3 && related.some(r => !readers.includes(r));
        addQuestion("cross-circuit-marker", "medium", related, [ledger.location],
          `Is ${ledger.name} enforced by every competing transition, including timeout, refund, repeat and recovery paths? Which states are truly terminal or one-time?`, "May-read/write graph only; a reader may inspect an unrelated revision or route.", unguarded ? 84 : competition ? 82 : 55, [unguarded ? "one-time marker write lacks guard" : "competing marker transitions", "cross-circuit state graph"]);
      }
    }
    for (const finding of report.findings) {
      const rows = report.circuits.filter(r => r.findings.includes(finding));
      addQuestion("audit-finding", ["critical", "high"].includes(finding.severity) ? "high" : "medium", rows, [finding.location], finding.message, `Audit-default detector ${finding.detectorId}; review required.`, ["critical", "high"].includes(finding.severity) ? 88 : 65, [`audit finding ${finding.detectorId}`]);
    }
    report.questions.sort((a, b) => b.score - a.score || ["high", "medium", "low"].indexOf(a.priority) - ["high", "medium", "low"].indexOf(b.priority) || a.id.localeCompare(b.id));
    report.questions.forEach((question, index) => { question.rank = index + 1; });
    report.questionSummary = { visible: Math.min(10, report.questions.length), collapsed: Math.max(0, report.questions.length - 10), generated: report.questions.length };
    for (const source of report.identity.sources) if (hash(readFileSync(source.file, "utf8")) !== source.sha256)
      throw new AnalysisError({ code: "review-source-changed", message: "Source changed during brief generation; evidence identity is invalid", location: at(source.file) });
    if (!program.entries.length) throw new AnalysisError({ code: "review-no-entrypoints", message: "No application entrypoints available for review", location: at(file) });
    report.status = scan.status === "complete" && report.coverage.inventory === "complete" && report.coverage.histories === "complete" ? "complete" : "incomplete";
  } catch (error) {
    report.status = "incomplete";
    report.coverage.diagnostics.push(error instanceof AnalysisError ? error.diagnostic : { code: "review-error", message: error instanceof Error ? error.message : String(error), location: at(file) });
  }
  return present(report, false);
}

export async function reviewFileIsolated(file: string, options: ReviewOptions = {}, limits: ExecutionLimits = {}): Promise<ReviewBrief> {
  try {
    const { stdout } = await runNodeModule(fileURLToPath(new URL("../runtime/worker.js", import.meta.url)), { kind: "review", path: resolve(file), options }, limits);
    const report = JSON.parse(stdout) as ReviewBrief;
    if (report.schemaVersion !== "nightshade-review-1" || !["complete", "incomplete"].includes(report.status) || !Array.isArray(report.circuits)
      || !Array.isArray(report.questions) || !Array.isArray(report.coverage?.diagnostics) || !report.identity || !report.stateMachine
      || !report.questionSummary || !report.summary || !report.pathFormat
      || report.status === "complete" && (report.coverage.diagnostics.length || report.coverage.histories !== "complete" || report.coverage.inventory !== "complete"))
      throw new WorkerFailure("worker-protocol", "Review worker returned an invalid brief");
    if (report.semanticProfile && report.semanticProfile !== semanticProfile(options.zkirVersion, options.compilerVersion))
      throw new WorkerFailure("worker-protocol", "Review worker returned a different compiler profile");
    return present(report);
  } catch (error) {
    const report = empty(file, options);
    report.coverage.diagnostics.push({ code: error instanceof WorkerFailure ? error.code : "review-worker-error", message: error instanceof Error ? error.message : String(error), location: at(file) });
    return present(report);
  }
}
export { reviewMarkdown } from "./review-presentation.js";
