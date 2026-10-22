#!/usr/bin/env node
// Internal compatibility-harness adapter. Use the matching built public API;
// ordinary CLI configuration intentionally requires a nonempty rule selection.
import { pathToFileURL } from 'node:url';

const [index, requestJson] = process.argv.slice(2);
const { file, options } = JSON.parse(requestJson);
const { scanFileIsolated } = await import(pathToFileURL(index).href);
const report = await scanFileIsolated(file, { ...options, detectors: [] });
if (report.findings.length || report.coverage.detectors.length) throw new Error('Baseline adapter selected security rules');
console.log(JSON.stringify(report));
process.exitCode = report.status === 'complete' ? 0 : 2;
