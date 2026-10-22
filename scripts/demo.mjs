import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const build = new URL('../dist/src/index.js', import.meta.url);
if (!existsSync(build)) {
  console.error('Build Nightshade first: npm ci && npm run build');
  process.exit(2);
}
const { scanFileIsolated } = await import(build.href);
const { human } = await import('../dist/src/reporting/index.js');
const directory = new URL('../examples/review/', import.meta.url);
const expected = JSON.parse(readFileSync(new URL('expected.json', directory), 'utf8'));
for (const [name, target] of Object.entries(expected)) {
  const result = await scanFileIsolated(fileURLToPath(new URL(name, directory)), { compilerVersion: '0.34.0' });
  console.log(`\n${name}\n${human(result)}`);
  assert.deepEqual(result.diagnostics, [], `${name}: unexpected diagnostic`);
  assert.deepEqual({ status: result.status, findings: result.findings.map(f => ({ detectorId: f.detectorId, severity: f.severity, line: f.location.line, column: f.location.column })) }, target, `${name}: expected output changed`);
}
console.log('\nDemo passed: expected finding and corrected control verified.');
