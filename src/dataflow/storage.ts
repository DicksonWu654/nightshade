import { transientDependencies, uncertainTransientDependencies } from "./transient-origins.js";
import type { AbstractValue, StateWrite } from "./index.js";
import type { Span } from "../model.js";
import { type Region, covers, mayOverlap, regionFromKey, regionKey } from "./regions.js";
import { checkpointDependencies, combine, constantOf } from "./transfers.js";
import { payloadDependencies } from "./either-payloads.js";
import { typeArguments } from "../semantic/types.js";

/** The current payload store. Collection membership, guards and effects are
 * separate domains; a payload read alone never proves a Map lookup succeeds. */
export interface StorageState {
  ledger: Map<string, AbstractValue>;
  ledgerVersions: Map<string, number>;
}
export interface RecordedStorageState extends StorageState {
  excluded: Map<string, Set<string>>;
  guards: Set<string>;
  writes: StateWrite[];
}
export interface StorageServices<S extends StorageState> {
  typedValue(type: string, leaf: () => AbstractValue): AbstractValue;
  refine(state: S, value: AbstractValue): AbstractValue;
  nextSnapshot(): number;
  nextWrite(): number;
  rootType(root: string): string;
  representationOf(type: string): string;
  fieldsOf(type: string): Record<string, string> | undefined;
  guardReads(guard: string, root: string): boolean;
}

export function selectStorageValue(value: AbstractValue, selection: AbstractValue): AbstractValue {
  return { ...value, ...transientDependencies([value, selection]), ...checkpointDependencies([value, selection]), ...payloadDependencies([value, selection]), flows: combine([value, selection]).flows,
    fields: value.fields ? Object.fromEntries(Object.entries(value.fields).map(([name, field]) => [name, selectStorageValue(field, selection)])) : undefined,
    items: value.items?.map(item => selectStorageValue(item, selection)) };
}

/** Conservative alias view only. Exact origins and predicate identities cannot
 * survive a union merely because both values mention the same dependencies. */
export function joinStorageValues(values: AbstractValue[], canonicalFlows = false): AbstractValue {
  const first = values[0], constant = constantOf(first);
  const same = constant && values.every(value => constantOf(value)?.kind === constant.kind && constantOf(value)?.value === constant.value);
  const fields = first.fields && values.every(value => value.fields && Object.keys(first.fields!).every(field => field in value.fields!))
    ? Object.fromEntries(Object.keys(first.fields).map(field => [field, joinStorageValues(values.map(value => value.fields![field]), canonicalFlows)])) : undefined;
  const items = first.items && values.every(value => value.items?.length === first.items!.length)
    ? first.items.map((_, index) => joinStorageValues(values.map(value => value.items![index]), canonicalFlows)) : undefined;
  const dependencies = combine(values);
  if (canonicalFlows) dependencies.flows.sort((left, right) => left.source.id.localeCompare(right.source.id) || left.form.localeCompare(right.form) || Number(!!left.directPreimage) - Number(!!right.directPreimage));
  return { ...dependencies, ...uncertainTransientDependencies(values),
    ...(values.some(value => value.complementaryLineageLost || value.numericExpression?.numericType !== undefined) ? { complementaryLineageLost: true as const } : {}),
    ...(values.some(value => value.comparison || value.negated) || values.some(value => value.fields) && !fields
      || values.some(value => value.items) && !items ? { predicateStructureLost: true as const } : {}),
    type: first.type, constant: same ? constant.value : undefined, constantKind: same ? constant.kind : undefined, fields, items };
}

/** Shared ordinary read transfer. The caller supplies its existing value and
 * identity allocators and its current scalar/tree refinement; no new budgets. */
export function readStorageRegion<S extends StorageState>(state: S, region: NonNullable<AbstractValue["region"]>, services: StorageServices<S>): AbstractValue {
  const entries = [...state.ledger].map(([key, value]) => ({ region: regionFromKey(key, value.type ?? "unknown"), value }));
  const primary = entries.filter(entry => covers(entry.region, region)).sort((first, second) => second.region.path.length - first.region.path.length)[0];
  const project = (stored: AbstractValue, path: string[]): AbstractValue => {
    let value: AbstractValue | undefined = stored;
    for (const part of path) value = part.startsWith("field:") ? value?.fields?.[part.slice(6)] : undefined;
    if (value) return value;
    const dependencies = { ...combine([stored]), predicateStructureLost: true as const };
    dependencies.flows = dependencies.flows.map(flow => ({ ...flow, form: "derived" }));
    return services.typedValue(region.type, () => ({ ...dependencies, ledger: new Set([region.root]) }));
  };
  const result = primary ? project(primary.value, region.path.slice(primary.region.path.length))
    : services.typedValue(region.type, () => ({ flows: [], ledger: new Set([region.root]), preexistingLedger: new Set([region.root]) }));
  const aliases: AbstractValue[] = [];
  for (const entry of entries) {
    if (!mayOverlap(entry.region, region) || covers(entry.region, region)) continue;
    if (entry.region.path.length <= region.path.length) aliases.push(project(entry.value, region.path.slice(entry.region.path.length)));
    else if (!entry.region.path[region.path.length].startsWith("field:")) {
      aliases.push({ ...result, ...combine([result, entry.value]), identity: undefined, constant: undefined, constantKind: undefined });
    }
  }
  const joined = aliases.length ? joinStorageValues([result, ...aliases]) : result;
  const snapshot = region.path.includes("key:*") ? `snapshot:${services.nextSnapshot()}` : undefined;
  const identify = (value: AbstractValue, path: string[]): AbstractValue => ({
    ...value,
    identity: value.identity ?? (snapshot ? `${snapshot}:${JSON.stringify(path)}` : `ledger:${regionKey({ ...region, path: [...region.path, ...path] })}:${state.ledgerVersions.get(region.root) ?? 0}`),
    ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([name, field]) => [name, identify(field, [...path, `field:${name}`])])) } : {}),
    ...(value.items ? { items: value.items.map((item, index) => identify(item, [...path, `index:${index}`])) } : {}),
  });
  const identified = identify(snapshot ? { ...joined, identity: undefined } : joined, []);
  const refined = services.refine(state, { ...identified, region: { ...region, revision: state.ledgerVersions.get(region.root) ?? 0 } });
  return region.selection ? selectStorageValue(refined, region.selection) : refined;
}

/** Capture the selected before/after values and dominating guards before any
 * mutation invalidates them. This records one real ordered write, not a join. */
export function recordStorageWrite<S extends RecordedStorageState>(state: S, region: NonNullable<AbstractValue["region"]>, value: AbstractValue,
  location: Span, callPath: string[], callSites: Span[], services: StorageServices<S>): void {
  const before = readStorageRegion(state, region, services);
  state.writes.push({ ledger: region.root, region: [...region.path], location, before, after: value,
    excludedBefore: [...(before.identity ? state.excluded.get(before.identity) ?? [] : [])], guards: [...state.guards], callPath: [...callPath], callSites: callSites.slice() });
  for (const guard of state.guards) if (services.guardReads(guard, region.root)) state.guards.delete(guard);
}

/** Payload/revision update only. Callers must also invalidate collection/list/
 * tree facts and guards, and retain the real ordered effect before this update. */
export function writeStorageRegion<S extends StorageState>(state: S, region: NonNullable<AbstractValue["region"]>, value: AbstractValue, services: StorageServices<S>): void {
  state.ledgerVersions.set(region.root, (state.ledgerVersions.get(region.root) ?? 0) + 1);
  const key = regionKey(region), previous = state.ledger.get(key);
  const stored = previous && region.path.includes("key:*") ? joinStorageValues([previous, value]) : value;
  state.ledger.set(key, { ...stored, identity: stored.identity ?? `write:${services.nextWrite()}` });
  if (!region.path.includes("key:*")) for (const key of state.ledger.keys()) {
    const descendant = regionFromKey(key, "unknown");
    if (descendant.path.length > region.path.length && covers(region, descendant)) state.ledger.delete(key);
  }
  if (region.path.at(-1)?.startsWith("field:")) {
    let start = region.path.length - 1;
    while (start > 0 && region.path[start - 1].startsWith("field:")) start--;
    let type = services.rootType(region.root);
    for (const part of region.path.slice(0, start)) type = part.startsWith("field:") ? services.fieldsOf(type)?.[part.slice(6)] ?? "unknown"
      : typeArguments(services.representationOf(type).slice(services.representationOf(type).indexOf("<")))[1] ?? "unknown";
    const rootRegion: Region = { root: region.root, path: region.path.slice(0, start), type };
    const rootValue = readStorageRegion(state, rootRegion, services);
    const update = (current: AbstractValue, depth: number): AbstractValue => {
      const name = region.path[depth].slice(6);
      const fields = { ...current.fields, [name]: depth === region.path.length - 1 ? value : update(current.fields?.[name] ?? { flows: [], ledger: new Set() }, depth + 1) };
      return { ...current, ...combine(Object.values(fields)), fields, identity: `write:${services.nextWrite()}`, constant: undefined, constantKind: undefined };
    };
    state.ledger.set(regionKey(rootRegion), update(rootValue, start));
  }
}
