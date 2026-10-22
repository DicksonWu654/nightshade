import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { extname, isAbsolute } from "node:path";
import { isPromise } from "node:util/types";
import { AnalysisError, type Diagnostic, type Span } from "../model.js";
import { finding, unique, type Detector } from "../detectors/types.js";
import { DETECTOR_API_VERSION, DETECTOR_FACTS_VERSION, type CustomDetector, type CustomDetectorDefinition, type DetectorFinding, type FactCapability } from "../detector-api.js";
import type { AnalysisFacts } from "../dataflow/index.js";

const require = createRequire(import.meta.url);
const capabilities: FactCapability[] = ["predicates", "calls", "merkle", "collections", "initialization"];
export const customDetectorId = (id: unknown): id is CustomDetector["id"] => typeof id === "string" && /^custom-[a-z][a-z0-9-]{0,63}$/.test(id);

/** Deliberately explicit local files only. Auto-discovered project config cannot load code. */
export function loadDetectorModules(paths: string[] | undefined, location: Span, issues: Diagnostic[]): { detectors: Detector[]; definitions: CustomDetectorDefinition[] } {
  const result: { detectors: Detector[]; definitions: CustomDetectorDefinition[] } = { detectors: [], definitions: [] };
  if (paths === undefined) return result;
  if (!Array.isArray(paths) || paths.length > 32 || paths.some(path => typeof path !== "string" || !isAbsolute(path) || extname(path) !== ".cjs"))
    throw new AnalysisError({ code: "invalid-detector-module", message: "detectorModules must contain at most 32 absolute trusted local .cjs file paths", location });
  const files = new Set<string>(), ids = new Set<string>();
  for (const path of paths) {
    try {
      const file = realpathSync(path);
      if (files.has(file)) throw new Error("Duplicate detector module");
      files.add(file);
      delete require.cache[require.resolve(file)];
      const plugin = require(file) as CustomDetector;
      if (!plugin || plugin.apiVersion !== DETECTOR_API_VERSION || plugin.factsVersion !== DETECTOR_FACTS_VERSION)
        throw new Error("Expected detector apiVersion 1 and factsVersion 1");
      if (!customDetectorId(plugin.id) || ids.has(plugin.id)) throw new Error("Expected a distinct custom- detector ID");
      if (typeof plugin.description !== "string" || !plugin.description.trim() || typeof plugin.run !== "function"
        || !Array.isArray(plugin.requires) || [...plugin.requires].some(item => !capabilities.includes(item)) || new Set(plugin.requires).size !== plugin.requires.length)
        throw new Error("Expected description, synchronous run function and supported distinct fact requirements");
      ids.add(plugin.id);
      const definition: CustomDetectorDefinition = { apiVersion: 1, factsVersion: 1, id: plugin.id, description: plugin.description, requires: [...plugin.requires] };
      result.definitions.push(definition);
      result.detectors.push({ id: definition.id, description: definition.description, requires: [...definition.requires], run(facts, policies) {
        try {
          const { program, ...evidence } = facts;
          // Evidence/policies are detached per consumer; an accidental mutation cannot
          // erase engine incompleteness or alter another detector's observations.
          // Program is a borrowed query object and remains read-only by contract.
          const observations = plugin.run({ factsVersion: 1, facts: { program, ...structuredClone(evidence) }, policies: structuredClone(policies!),
            incomplete(message, at = facts.program.rootSource.ast.span) {
              if (typeof message !== "string" || !message.trim()) throw new Error("incomplete requires a meaningful message");
              validateFinding({ severity: "info", confidence: "low", title: "Incomplete", message, remediation: "Review incomplete custom analysis", location: at, trace: [], callPath: [], metadata: {} }, facts);
              issues.push({ code: "custom-detector-incomplete", message: `${definition.id}: ${message}`, location: at });
            },
          });
          // The API is synchronous. Consume a rejected native Promise before
          // diagnosing it so malformed output cannot cause an unhandled rejection.
          if (isPromise(observations)) { void observations.catch(() => {}); throw new Error("run must return a synchronous array of findings"); }
          if (!Array.isArray(observations)) throw new Error("run must return a synchronous array of findings");
          // Validate/detach all output before accepting any of this detector's findings.
          jsonData(observations);
          const detached = JSON.parse(JSON.stringify(observations)) as DetectorFinding[];
          for (const value of detached) validateFinding(value, facts);
          return unique(detached.map(({ discriminator, ...value }) => finding(facts, { ...value, detectorId: definition.id }, discriminator)));
        } catch (error) {
          issues.push({ code: "custom-detector-error", message: `${definition.id}: ${error instanceof Error ? error.message : String(error)}`, location });
          return [];
        }
      } });
    } catch (error) {
      throw new AnalysisError({ code: "detector-module-error", message: `${path}: ${error instanceof Error ? error.message : String(error)}`, location });
    }
  }
  return result;
}

function jsonData(value: unknown, parents = new Set<object>()): void {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number" && Number.isFinite(value)) return;
  if (!value || typeof value !== "object" || parents.has(value) || ![Object.prototype, Array.prototype, null].includes(Object.getPrototypeOf(value)))
    throw new Error("Findings must contain acyclic plain JSON data");
  parents.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (Array.isArray(value) && key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (typeof key !== "string" || !descriptor.enumerable || !("value" in descriptor)) throw new Error("Findings must contain plain data properties");
    if (!Array.isArray(value) && descriptor.value === undefined) continue;
    jsonData(descriptor.value, parents);
  }
  parents.delete(value);
}

function validateFinding(value: DetectorFinding, facts: AnalysisFacts): void {
  const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
  const span = (value: unknown): value is Span => {
    if (!object(value) || typeof value.file !== "string" || !facts.program.files.has(value.file)
      || Object.keys(value).some(key => !["file", "start", "end", "line", "column", "endLine", "endColumn"].includes(key))) return false;
    if (!["start", "end", "line", "column", "endLine", "endColumn"].every(key => Number.isSafeInteger(value[key]) && Number(value[key]) >= (["start", "end"].includes(key) ? 0 : 1))) return false;
    const text = facts.program.files.get(value.file)!.text;
    if (Number(value.end) < Number(value.start) || Number(value.end) > Buffer.byteLength(text)) return false;
    const start = sourcePosition(text, Number(value.start)), end = sourcePosition(text, Number(value.end));
    return !!start && !!end && start.line === value.line && start.column === value.column && end.line === value.endLine && end.column === value.endColumn;
  };
  if (!object(value) || Object.keys(value).some(key => !["severity", "confidence", "title", "message", "location", "source", "constraint", "trace", "callPath", "remediation", "metadata", "discriminator"].includes(key))
    || !["info", "low", "medium", "high", "critical"].includes(value.severity) || !["low", "medium", "high"].includes(value.confidence)
    || ![value.title, value.message, value.remediation].every(item => typeof item === "string" && item.trim()) || !span(value.location)
    || value.source !== undefined && !span(value.source) || value.constraint !== undefined && !span(value.constraint)
    || !Array.isArray(value.trace) || value.trace.some(step => !object(step) || Object.keys(step).some(key => !["kind", "label", "location"].includes(key)) || typeof step.kind !== "string" || typeof step.label !== "string" || !span(step.location))
    || !Array.isArray(value.callPath) || value.callPath.some(item => typeof item !== "string") || !object(value.metadata)
    || value.discriminator !== undefined && typeof value.discriminator !== "string") throw new Error("Invalid custom finding; use owned source spans and the DetectorFinding contract");
}

/** Same newline and UTF-8/UTF-16 convention as the owned parser view. */
function sourcePosition(text: string, target: number): { line: number; column: number } | undefined {
  let bytes = 0, line = 1, column = 1;
  for (let index = 0; index < text.length;) {
    if (bytes === target) return { line, column };
    const character = String.fromCodePoint(text.codePointAt(index)!);
    bytes += Buffer.byteLength(character); index += character.length;
    if (character === "\r" && ["\n", "\u0085"].includes(text[index])) { bytes += Buffer.byteLength(text[index]); index++; }
    if (["\n", "\r", "\u0085", "\u2028"].includes(character)) { line++; column = 1; }
    else column += character.length;
    if (bytes > target) return undefined;
  }
  return bytes === target ? { line, column } : undefined;
}
