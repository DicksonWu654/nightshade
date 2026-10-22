import { spawnSync, execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import ts from 'typescript';

// Conservative import closure: unmodeled inputs select the full suite. This is
// a developer fast path, never a replacement for milestone qualification.
const root = process.cwd();
const args = process.argv.slice(2);
const listOnly = args.includes("--list");
if (listOnly) args.splice(args.indexOf("--list"), 1);
let changed;
if (!args.length) {
  changed = [...execFileSync('git', ['diff', '--name-only', 'HEAD'], { encoding: 'utf8' }).trim().split('\n'),
    ...execFileSync('git', ['ls-files', '--others', '--exclude-standard'], { encoding: 'utf8' }).trim().split('\n')].filter(Boolean);
} else if (args[0] === '--since' && args.length === 2) changed = [...execFileSync('git', ['diff', '--name-only', args[1]], { encoding: 'utf8' }).trim().split('\n'), ...execFileSync('git', ['ls-files', '--others', '--exclude-standard'], { encoding: 'utf8' }).trim().split('\n')].filter(Boolean);
else if (args[0] === '--files' && args.length > 1) changed = args.slice(1);
else { console.error('Usage: npm run check:affected -- [--list] [--since REV | --files PATH ...]'); process.exit(2); }
const paths = [];
function visit(directory) {
  for (const item of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, item.name);
    if (item.isDirectory()) visit(path);
    else if (path.endsWith('.ts')) paths.push(path);
  }
}
visit(resolve('src')); visit(resolve('tests'));
const importers = new Map();
for (const file of paths) for (const dependency of ts.preProcessFile(readFileSync(file, 'utf8'), true, true).importedFiles) {
  if (!dependency.fileName.startsWith('.')) continue;
  const path = resolve(dirname(file), dependency.fileName).replace(/\.js$/, '.ts');
  const consumers = importers.get(path) ?? new Set(); consumers.add(file); importers.set(path, consumers);
}
const all = paths.filter(path => path.endsWith('.test.ts')).sort();
const seen = new Set(), pending = changed.map(path => resolve(path));
// Process launch and generated/fixture paths are not all TypeScript imports.
// Library changes therefore include every consumer of filesystem/process APIs;
// nested test-support and other unknown inputs fall back to the full suite.
const runtimeConsumers = paths.filter(file => /(?:node:|from ["'])(?:child_process|fs(?:\/promises)?)["']|\bimport\s*\((?!\s*["'])/.test(readFileSync(file, 'utf8')));
const libraryChange = changed.some(path => !path.endsWith('.test.ts'));
if (libraryChange) pending.push(...runtimeConsumers);
const unknown = changed.some(path => !path.endsWith('.ts') || !existsSync(resolve(path)) || !paths.includes(resolve(path)) || path.startsWith('tests/') && dirname(path) !== 'tests');
while (pending.length) {
  const path = pending.pop(); if (seen.has(path)) continue; seen.add(path);
  for (const consumer of importers.get(path) ?? []) pending.push(consumer);
}
const selected = unknown ? all : all.filter(path => seen.has(path));
if (changed.length && !selected.length) { console.error('No proven test mapping; selecting full correctness suite.'); selected.push(...all); }
console.error(`Affected checks: ${changed.length} changed paths; ${selected.length}/${all.length} test files${unknown ? ' (unmodeled input: full fallback)' : ''}. Full suite remains required at milestones.`);
if (listOnly) { console.log(JSON.stringify(selected.map(path => relative(root, path)))); process.exit(0); }
const built = spawnSync('npm', ['run', 'build:incremental'], { stdio: 'inherit' });
if (built.status !== 0) process.exit(built.status ?? 1);
if (!selected.length) process.exit(0);
const result = spawnSync(process.execPath, ['scripts/test.mjs', 'correctness', ...selected.map(path => resolve('dist', relative(root, path).replace(/\.ts$/, '.js')))], { stdio: 'inherit' });
process.exit(result.status ?? 1);
