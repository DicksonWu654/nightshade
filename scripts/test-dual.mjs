import { execFileSync, spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { availableParallelism } from 'node:os';

// Build once beforehand. The N-API parser and tree-sitter runtime are shared
// without a concurrent rebuild; each Node runs every correctness assertion.
const versions = [process.env.NIGHTSHADE_NODE22, process.env.NIGHTSHADE_NODE24];
if (versions.some(path => !path)) { console.error('Set NIGHTSHADE_NODE22 and NIGHTSHADE_NODE24 to the pinned Node executable paths; build before running.'); process.exit(2); }
const identities = versions.map((node, index) => {
  const identity = execFileSync(node, ['--version'], { encoding: 'utf8' }).trim();
  if (!identity.startsWith(`v${index ? 24 : 22}.`)) throw new Error(`Expected Node ${index ? 24 : 22}, got ${identity}`);
  return identity;
});
console.error(`Dual-Node executables: ${identities.join(' / ')}.`);
const concurrency = Math.max(1, Math.min(16, Math.floor(availableParallelism() / 2)));
const start = performance.now();
const env = { ...process.env };
// Runner executable selectors do not belong to compiler fixture identity.
delete env.NIGHTSHADE_NODE22; delete env.NIGHTSHADE_NODE24;
const results = await Promise.all(versions.map((node, index) => new Promise(resolveResult => {
  const child = spawn(node, [resolve('scripts/test.mjs'), 'correctness', '--concurrency', String(concurrency)], { stdio: ['ignore', 'pipe', 'pipe'], env });
  child.stdout.on('data', data => process.stdout.write(`[${identities[index]}] ${data}`));
  child.stderr.on('data', data => process.stderr.write(`[${identities[index]}] ${data}`));
  child.on('error', error => { console.error(error.message); resolveResult(1); });
  child.on('close', code => { console.error(`[${identities[index]}] exit ${code ?? 1}.`); resolveResult(code ?? 1); });
})));
console.error(`Dual-Node correctness: ${(performance.now() - start).toFixed(0)} ms, ${concurrency} workers per version, exits ${results.join('/')}.`);
process.exitCode = results.every(code => code === 0) ? 0 : 1;
