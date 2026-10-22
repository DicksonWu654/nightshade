import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { Dataflow, type AbstractValue, type SuccessfulPredicate, type TraceStep } from "../dataflow/index.js";
import { ValueFingerprints } from "../dataflow/fingerprints.js";
import { Program } from "../semantic/index.js";
import { semanticProfile, validCompilerVersion, validSemanticProfile } from "../semantic/profile.js";
import { AnalysisError, type Diagnostic, type Span } from "../model.js";
import type { ScanOptions } from "../index.js";
import { runNodeModule, WorkerFailure, type ExecutionLimits } from "../runtime/process.js";

export const auditorPrinters = ["human-summary", "ledger-access", "disclosure-map", "data-dependency"] as const;
export type AuditorPrinter = typeof auditorPrinters[number];
export type AuditorOptions = Pick<ScanOptions, "searchPaths" | "sourceRoot" | "compilerVersion" | "zkirVersion" | "maxSteps" | "maxPaths" | "maxValues">;
export interface AuditReport {
  schemaVersion: "nightshade-auditor-1";
  analysisKind: "successful-history-printer";
  printer: AuditorPrinter;
  status: "complete" | "incomplete";
  semanticProfile?: string;
  scope: string;
  diagnostics: Diagnostic[];
  entries: { id: string; name: string; location: Span; status: "complete" | "incomplete"; histories: number; writes: number; publicSinks: number; reads: string[]; mutates: string[] }[];
  data: unknown;
}

const location = (path: string): Span => ({ file: resolve(path), start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 });
function empty(printer: AuditorPrinter, options: AuditorOptions = {}): AuditReport {
  return { schemaVersion: "nightshade-auditor-1", analysisKind: "successful-history-printer", printer, status: "incomplete",
    semanticProfile: semanticProfile(options.zkirVersion, options.compilerVersion),
    scope: "Modeled successful invocation histories only, not transaction reachability or proof of authorization. Predicates retain their original storage revisions; preceding checks need not constrain current storage. Required evidence is an intersection at a write site, only for complete entries. Completed calls are not security guards. Disclose permission alone is not publication.",
    diagnostics: [], entries: [], data: null };
}

/** A compact DAG preserves immutable values, revisions and full provenance without
 * expanding shared aggregate operands repeatedly. Output is still worker-bounded. */
class Evidence {
  readonly values: Record<string, unknown> = {};
  readonly sources: Record<string, unknown> = {};
  readonly traces: Record<string, unknown> = {};
  private readonly ids = new WeakMap<AbstractValue, string>();
  private readonly pending = new WeakSet<AbstractValue>();
  private readonly valueKeys = new Map<string, string>();
  private readonly sourceKeys = new Map<string, string>();
  private readonly traceKeys = new Map<string, string>();
  private readonly encoded = new WeakMap<object, Map<string, unknown>>();
  private work = 0;
  constructor(private readonly span: Span) {}
  private intern(input: unknown, keys: Map<string, string>, table: Record<string, unknown>, prefix: string): string {
    const hash = createHash("sha256").update(JSON.stringify(input)).digest("hex");
    let id = keys.get(hash);
    if (!id) { id = `${prefix}${keys.size + 1}`; keys.set(hash, id); table[id] = input; }
    return id;
  }
  private trace(steps: readonly TraceStep[]): { trace: string | null } {
    let prefix: string | null = null;
    for (const step of steps) {
      if (++this.work > 1000000) throw new AnalysisError({ code: "printer-budget", message: "Auditor trace serialization exceeded its bounded work; output is incomplete", location: this.span });
      prefix = this.intern({ prefix, step }, this.traceKeys, this.traces, "t");
    }
    return { trace: prefix };
  }
  encode(input: unknown, depth = 0, field?: string): unknown {
    if (++this.work > 1000000 || depth > 256) throw new AnalysisError({ code: "printer-budget", message: "Auditor evidence serialization exceeded its bounded work/depth; output is incomplete", location: this.span });
    if (!input || typeof input !== "object") return input;
    const role = field === "trace" && Array.isArray(input) ? "trace"
      : field === "source" && "id" in input && "location" in input ? "source" : "plain";
    const cached = this.encoded.get(input)?.get(role);
    if (cached !== undefined) return cached;
    const encoded = this.encodeObject(input, depth, role);
    let roles = this.encoded.get(input);
    if (!roles) { roles = new Map(); this.encoded.set(input, roles); }
    roles.set(role, encoded);
    return encoded;
  }
  private encodeObject(input: object, depth: number, role: string): unknown {
    if (input instanceof Set || input instanceof Map) return this.encode([...input], depth + 1);
    if (role === "trace") return this.trace(input as TraceStep[]);
    if (role === "source")
      return { source: this.intern(input, this.sourceKeys, this.sources, "s") };
    if (Array.isArray(input)) return input.map(value => this.encode(value, depth + 1));
    if (input && typeof input === "object") {
      const value = input as AbstractValue;
      if (Array.isArray(value.flows) && value.ledger instanceof Set) {
        let id = this.ids.get(value);
        if (!id) {
          if (this.pending.has(value)) throw new Error("Cyclic abstract value in auditor evidence");
          this.pending.add(value);
          const encoded = Object.fromEntries(Object.entries(input).map(([key, part]) => [key, this.encode(part, depth + 1, key)]));
          // Equality includes full source and trace references, not the engine's
          // trace-insensitive semantic fingerprint. No provenance is discarded.
          id = this.intern(encoded, this.valueKeys, this.values, "v");
          this.ids.set(value, id); this.pending.delete(value);
        }
        return { value: id };
      }
      return Object.fromEntries(Object.entries(input).map(([key, part]) => [key, this.encode(part, depth + 1, key)]));
    }
    return input;
  }
}

export function auditFile(path: string, printer: AuditorPrinter, options: AuditorOptions = {}): AuditReport {
  const report = empty(printer, options);
  try {
    if (!auditorPrinters.includes(printer)) throw new Error("Unknown auditor printer");
    for (const budget of [options.maxSteps, options.maxPaths, options.maxValues]) if (budget !== undefined && (!Number.isSafeInteger(budget) || budget < 1)) throw new Error("Analysis budgets must be positive safe integers");
    const program = new Program(resolve(path), options.searchPaths, options.sourceRoot, undefined, options.zkirVersion, options.compilerVersion);
    report.semanticProfile = program.semanticProfile;
    // Full predicates and genuine histories: query witnesses cannot establish
    // universal guard evidence or enumerate the public sinks of an entry.
    const facts = new Dataflow(program, options.maxSteps, options.maxPaths, options.maxValues, "instructions", true, true, "equivalent-states", false, true, "all").analyze();
    report.diagnostics = [...facts.diagnostics];
    const complete = new Set(facts.completedEntries);
    report.entries = program.entries.map(id => {
      const fn = program.functions.get(id)!;
      const paths = facts.paths.filter(path => path.entry === id);
      return { id, name: fn.symbol.name, location: fn.declaration.span, status: complete.has(id) ? "complete" : "incomplete", histories: paths.length,
        writes: paths.reduce((sum, path) => sum + path.writes.length, 0), publicSinks: paths.reduce((sum, path) => sum + path.sinks.length, 0),
        reads: [...fn.readsState].sort(), mutates: [...fn.writesState].sort() };
    });
    if (!program.entries.length) report.diagnostics.push({ code: "no-entrypoints", message: "No application entrypoints found; use a structural printer for library templates", location: location(path) });
    report.status = report.diagnostics.length || complete.size !== program.entries.length ? "incomplete" : "complete";
    const symbols = program.activeSymbols().filter(symbol => ["ledger", "circuit", "constructor", "witness"].includes(symbol.kind))
      .map(symbol => ({ id: symbol.id, name: symbol.name, kind: symbol.kind, location: symbol.span }));
    if (printer === "human-summary") { report.data = { symbols, metrics: facts.metrics }; return report; }
    const evidence = new Evidence(location(path));
    const fingerprints = new ValueFingerprints();
    const predicates: Record<string, unknown> = {};
    const predicateKeys = new Map<string, string>();
    const predicateId = (predicate: SuccessfulPredicate): string => {
      const encoded = evidence.encode(predicate);
      const key = createHash("sha256").update(JSON.stringify(encoded)).digest("hex");
      let id = predicateKeys.get(key);
      if (!id) { id = `p${predicateKeys.size + 1}`; predicateKeys.set(key, id); predicates[id] = encoded; }
      return id;
    };
    const sites = new Map<string, { entry: string; ledger: string; region: string[]; location: Span; callPath: string[]; callSites?: Span[]; occurrences: number; requiredPredicates: Set<string>; requiredCompletedCalls: Set<string> }>();
    const histories = facts.paths.map((path, history) => {
      const base = { history, entry: path.entry, trace: evidence.encode(path.path, 0, "trace") };
      if (printer === "ledger-access") return { ...base, writes: path.writes.map((write, index) => {
        const preceding = (path.predicates ?? []).filter(predicate => predicate.writesBefore <= index).map(predicateId);
        const { ledger, region, location, callPath, callSites } = write;
        const siteId = fingerprints.key({ entry: path.entry, ledger, region, location, callPath, callSites });
        const site = sites.get(siteId);
        if (site) {
          site.occurrences++;
          site.requiredPredicates = new Set([...site.requiredPredicates].filter(id => preceding.includes(id)));
          site.requiredCompletedCalls = new Set([...site.requiredCompletedCalls].filter(id => write.guards.includes(id)));
        } else sites.set(siteId, { entry: path.entry, ledger, region, location, callPath, callSites, occurrences: 1, requiredPredicates: new Set(preceding), requiredCompletedCalls: new Set(write.guards) });
        return { site: siteId, index, ledger, region, location, callPath, callSites, before: evidence.encode(write.before), after: evidence.encode(write.after),
          enforcedBeforeWrite: preceding, completedCallsStillValid: write.guards };
      }) };
      if (printer === "disclosure-map") return { ...base, sinks: path.sinks.map(sink => ({ ...sink, value: evidence.encode(sink.value) })) };
      return { ...base, dependencies: [
        ...path.writes.map(write => ({ target: "ledger-write", name: write.ledger, location: write.location, value: write.after })),
        ...path.sinks.map(sink => ({ target: sink.kind, name: sink.name, location: sink.location, value: sink.value })),
      ].map(item => ({ ...item, value: evidence.encode(item.value), privateSources: evidence.encode(item.value.flows), ledgerSources: [...item.value.ledger].sort() })) };
    });
    report.data = { symbols, histories, values: evidence.values, sources: evidence.sources, traces: evidence.traces, ...(printer === "ledger-access" ? { predicates,
      sites: [...sites].map(([id, site]) => ({ ...site, id, requiredPredicates: complete.has(site.entry) ? [...site.requiredPredicates] : null,
        requiredCompletedCalls: complete.has(site.entry) ? [...site.requiredCompletedCalls] : null })) } : {}) };
  } catch (error) {
    report.status = "incomplete"; report.data = null;
    report.diagnostics.push(error instanceof AnalysisError ? error.diagnostic : { code: "printer-error", message: error instanceof Error ? error.message : String(error), location: location(path) });
  }
  return report;
}

export async function auditFileIsolated(path: string, printer: AuditorPrinter, options: AuditorOptions = {}, limits: ExecutionLimits = {}): Promise<AuditReport> {
  try {
    const { stdout } = await runNodeModule(fileURLToPath(new URL("../runtime/worker.js", import.meta.url)), { kind: "audit", path, printer, options }, limits);
    const report = JSON.parse(stdout) as AuditReport;
    const profileMatches = validSemanticProfile(report.semanticProfile) && (!validCompilerVersion(options.compilerVersion) || report.semanticProfile === semanticProfile(options.zkirVersion, options.compilerVersion))
      && ((options.zkirVersion === 3) === (report.semanticProfile === semanticProfile(3)));
    if (report.schemaVersion !== "nightshade-auditor-1" || report.analysisKind !== "successful-history-printer" || report.printer !== printer || !profileMatches
      || !["complete", "incomplete"].includes(report.status) || !Array.isArray(report.entries) || !Array.isArray(report.diagnostics)
      || report.status === "complete" && (report.diagnostics.length > 0 || report.entries.length === 0 || report.entries.some(entry => entry.status !== "complete") || report.data === null))
      throw new WorkerFailure("worker-protocol", "Auditor worker did not return a supported report for the requested view/profile");
    return report;
  } catch (error) {
    const report = empty(printer, options);
    report.diagnostics.push({ code: error instanceof WorkerFailure ? error.code : "printer-worker-error", message: error instanceof Error ? error.message : String(error), location: location(path) });
    return report;
  }
}

export function humanSummary(report: AuditReport): string {
  return [`Nightshade auditor: ${report.status} (${report.semanticProfile ?? "profile unavailable"})`, report.scope,
    ...report.entries.map(entry => `${entry.name}: ${entry.status}; ${entry.histories} successful histories; ${entry.writes} write occurrences; ${entry.publicSinks} public sink occurrences\n  ${entry.location.file}:${entry.location.line}`),
    ...report.diagnostics.map(diagnostic => `${diagnostic.code}: ${diagnostic.message} (${diagnostic.location.file}:${diagnostic.location.line})`)].join("\n");
}
