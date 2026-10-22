import { relative } from "node:path";
import type { Program } from "../semantic/index.js";
import type { EndpointCharge } from "../semantic/refund-endpoint.js";
import type { RefundEndpointCertificate } from "../dataflow/refund-endpoint.js";
import { isRefundEndpointCertificate } from "../dataflow/refund-endpoint.js";
import { REFUND_ENDPOINT_RULE } from "../semantic/refund-endpoint.js";
import { finding, type Detector } from "./types.js";
const endpointText = Object.freeze({
  "title": "Local refund formula accepts the selected zero remainder witness",
  "message": "A complete inspected pure validator accepts the formal endpoint B=P=A=Q=1, and the tied canonical send expression is checked unsigned B-Q. The inspected local arithmetic constraints do not exclude this selected endpoint. Review explicit zero handling. Other caller conditions and effects may preclude execution; this source-local formula certificate does not establish reachable ledger inputs, a successful history, transaction feasibility, send rejection or a requirement to prohibit zero.",
  "remediation": "Review whether this allocation endpoint should skip a zero remainder send; intentional endpoints remain valid application choices.",
  "constraintLabel": "Complete pure refund formula",
  "callLabel": "Canonical remainder send expression"
});
const endpointMetadata = Object.freeze({
  reviewRequired: true, formalWitness: Object.freeze(["1", "1", "1", "1"]),
  successfulHistory: "not-certified", ledgerFeasibility: "not-proven", sendRejection: "not-inferred",
  fullRecordRecallCredit: false, otherCallerConstraints: "not-certified",
});

/** Reserve actual emitted strings and both this bounded fingerprint rehearsal
 * and finding()'s file-list/sort/path/replacement/hash preparation. Pathname
 * storage is represented by compilation-local tokens throughout this estimate.
 * Every temporary is charged before allocation; there is no fixed text estimate. */
export function reserveRefundEndpointFinding(program: Program, certificate: RefundEndpointCertificate, charge: EndpointCharge): void {
  const { candidate } = certificate;
  const name = program.symbols.get(candidate.entry)!.name;
  charge(1, 64); // finding/metadata/trace/callPath/witness/report containers
  let textLength = REFUND_ENDPOINT_RULE.length + 4 + 4 + certificate.scope.length + certificate.formula.length
    + name.length * 2 + program.meteringPath(candidate.send.file).length + program.meteringPath(candidate.assertion.file).length;
  for (const [key, value] of Object.entries(endpointText)) { charge(1, 2); textLength += key.length + value.length; }
  for (const [key, value] of Object.entries(endpointMetadata)) {
    charge(1, 2); textLength += key.length;
    if (typeof value === "string") textLength += value.length;
    else if (Array.isArray(value)) for (const item of value) { charge(); textLength += item.length; }
  }
  // Actual finding field names, dynamic metadata keys, trace tags and digest.
  textLength += "detectorIdseverityconfidencetitlemessagelocationconstrainttracecallPathremediationmetadatafingerprint".length
    + "certificateScopeformulaentrykindlabellocation".length + "constraintcall".length + 64;
  charge(1 + Math.ceil(textLength / 32), Math.ceil(textLength / 8));

  const count = program.files.size;
  charge(2 + 2 * count * count, 4 + 4 * count); // two key lists and sorts
  const files = [...program.files.keys()].map(file => ({
    file: "/" + program.meteringPath(file), normalized: program.meteringPath(file),
  })).sort((left, right) => right.file.length - left.file.length);
  const initialLength = program.meteringIdentity(candidate.entry).length + 1 + 16; // bounded source offset digits
  charge(1 + Math.ceil(initialLength / 32), 2 * Math.ceil(initialLength / 8));
  let discriminator = `/${program.meteringIdentity(candidate.entry)}:${candidate.send.start}`;
  const root = "/";
  for (const { file, normalized } of files) {
    // relative() normalizes/splits both paths; reserve a conservative linear
    // workspace and output bound for the rehearsal and the future finding().
    const pathLength = root.length + file.length + 4;
    charge(2 + Math.ceil(8 * pathLength / 32), 2 * Math.ceil(8 * pathLength / 8));
    let occurrences = 0, offset = 0, resultLength = discriminator.length;
    while (offset <= discriminator.length) {
      charge(1 + Math.ceil((discriminator.length + file.length) / 32));
      const found = discriminator.indexOf(file, offset);
      if (found < 0) break;
      resultLength += normalized.length - file.length;
      if (!Number.isSafeInteger(resultLength)) throw new Error("Refund fingerprint replacement length exceeds bounded work");
      occurrences++; offset = found + file.length;
    }
    const scanLength = discriminator.length + file.length + normalized.length;
    charge(2 + Math.ceil(2 * ((occurrences + 1) * scanLength + resultLength) / 32), 2 * Math.ceil(resultLength / 8));
    discriminator = discriminator.replaceAll(file, () => normalized);
  }
  const rootLength = root.length + program.meteringPath(program.root).length + 4;
  const siteLength = root.length + program.meteringPath(candidate.send.file).length + 4;
  charge(2 + Math.ceil(8 * (rootLength + siteLength) / 32), 2 * Math.ceil(8 * (rootLength + siteLength) / 8));
  const rootPath = relative(root, "/" + program.meteringPath(program.root)), sitePath = relative(root, "/" + program.meteringPath(candidate.send.file));
  const keyLength = REFUND_ENDPOINT_RULE.length + rootPath.length + sitePath.length + 16 + discriminator.length + 4;
  // Joining the fingerprint key and UTF-8 encoding for SHA256, plus output.
  charge(2 + Math.ceil(4 * keyLength / 32), Math.ceil(6 * keyLength / 8) + 64);
}
export const unshieldedRefundEndpointReview: Detector = {
  id: REFUND_ENDPOINT_RULE, defaultEnabled: false, description: "Review a complete local refund-validator endpoint producing a zero remainder send expression",
  requires: ["source-local-formula-certificate"],
  run(facts) {
    const evidence = facts.refundEndpointEvidence;
    if (!evidence || evidence.version !== 1 || evidence.program !== facts.program || evidence.compilerVersion !== facts.program.compilerVersion || evidence.zkirVersion !== facts.program.zkirVersion) return [];
    return evidence.certificates.filter(certificate => {
      const declaration = facts.program.functions.get(certificate.candidate.entry)?.declaration;
      return isRefundEndpointCertificate(certificate, facts.program) && certificate.scope === "source-local-formula" && facts.program.entries.includes(certificate.candidate.entry)
        && declaration?.span.file === certificate.candidate.send.file && declaration.span.start <= certificate.candidate.send.start
        && declaration.span.end >= certificate.candidate.send.end && certificate.witness.length === 4 && certificate.witness.every(value => value === 1n);
    }).map(certificate => {
      const { candidate } = certificate;
      return finding(facts, {
        detectorId: REFUND_ENDPOINT_RULE, severity: "info", confidence: "high",
        title: endpointText.title,
        message: endpointText.message,
        location: candidate.send, constraint: candidate.assertion,
        trace: [{ kind: "constraint", label: endpointText.constraintLabel, location: candidate.assertion },
          { kind: "call", label: endpointText.callLabel, location: candidate.send }],
        callPath: [facts.program.symbols.get(candidate.entry)!.name],
        remediation: endpointText.remediation,
        metadata: { ...endpointMetadata, certificateScope: certificate.scope, formula: certificate.formula,
          entry: facts.program.symbols.get(candidate.entry)!.name,
          },
      }, `${candidate.entry}:${candidate.send.start}`);
    });
  },
};
