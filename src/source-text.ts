export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n|\r\u0085|[\r\u0085\u2028]/g, "\n");
}
