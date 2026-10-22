import { copyFileSync, mkdirSync } from "node:fs";

// Keep the measured/packed dist tree self-contained, including pinned sources.
const destination = new URL("../dist/src/stdlib/", import.meta.url);
mkdirSync(destination, { recursive: true });
for (const name of ["standard-library", "standard-library-0.28", "standard-library-0.29", "standard-library-0.30", "standard-library-0.33-rc.2", "standard-library-0.35-rc.1", "zkir-v3-library"]) {
  copyFileSync(new URL(`../src/stdlib/${name}.compact`, import.meta.url), new URL(`${name}.compact`, destination));
}
