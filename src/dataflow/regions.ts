export interface Region {
  root: string;
  path: string[];
  type: string;
}

export function regionKey(region: Region): string {
  return JSON.stringify([region.root, ...region.path]);
}

export function regionFromKey(key: string, type: string): Region {
  const [root, ...path] = JSON.parse(key) as string[];
  return { root, path, type };
}

export function mayOverlap(first: Region, second: Region): boolean {
  return first.root === second.root && first.path.slice(0, second.path.length).every((part, index) =>
    part === second.path[index]
      || (part === "key:*" || second.path[index] === "key:*") && part.startsWith("key:") && second.path[index].startsWith("key:")
      // A bounded immutable dynamic operand is still a may-alias of every
      // concrete key. CollectionFacts keeps its identity for repeated-key
      // correlation; storage-region overlap must remain conservative.
      || part.startsWith("key:identity:") && second.path[index].startsWith("key:")
      || second.path[index].startsWith("key:identity:") && part.startsWith("key:"));
}

export function covers(ancestor: Region, descendant: Region): boolean {
  return ancestor.root === descendant.root && !ancestor.path.includes("key:*") && ancestor.path.length <= descendant.path.length && ancestor.path.every((part, index) => part === descendant.path[index]);
}
