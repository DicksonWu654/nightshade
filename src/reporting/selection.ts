import { relative, sep } from "node:path";
import { fail, type Span } from "../model.js";

export function validateExclusions(patterns: unknown, location: Span): string[] {
  if (!Array.isArray(patterns) || patterns.length > 128 || patterns.some(pattern => typeof pattern !== "string" || !pattern.length || pattern.length > 1024
    || pattern.startsWith("/") || /^[A-Za-z]:/.test(pattern) || /[\\\[\]{}!\x00-\x1f]/.test(pattern) || pattern.includes("//") || pattern.split("/").some(part => part === "." || part === ".." || part.includes("**") && part !== "**")))
    fail("invalid-exclusion", "Use at most 128 relative /-separated exclusion patterns with *, ? and whole-segment ** (1024 characters each)", location);
  return patterns as string[];
}

/** Bounded dynamic programming avoids regex backtracking on user globs. */
function segment(pattern: string, name: string): boolean {
  let row = Array<boolean>(name.length + 1).fill(false); row[0] = true;
  for (const character of pattern) {
    const next = Array<boolean>(name.length + 1).fill(false);
    if (character === "*") next[0] = row[0];
    for (let index = 1; index <= name.length; index++) next[index] = character === "*" ? row[index] || next[index - 1]
      : row[index - 1] && (character === "?" || character === name[index - 1]);
    row = next;
  }
  return row[name.length];
}

export function excludedRoot(path: string, root: string, patterns: readonly string[]): boolean {
  const parts = relative(root, path).split(sep).join("/").split("/");
  return patterns.some(pattern => {
    let row = Array<boolean>(parts.length + 1).fill(false); row[0] = true;
    for (const piece of (pattern.endsWith("/") ? pattern + "**" : pattern).split("/")) {
      const next = Array<boolean>(parts.length + 1).fill(false);
      if (piece === "**") next[0] = row[0];
      for (let index = 1; index <= parts.length; index++) next[index] = piece === "**" ? row[index] || next[index - 1]
        : row[index - 1] && segment(piece, parts[index - 1]);
      row = next;
    }
    return row[parts.length];
  });
}
