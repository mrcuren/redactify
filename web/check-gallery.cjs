// Verifies that the WebAssembly module reproduces the gallery written by the
// native `gen-gallery` binary, example by example: the page's live demo and
// its example gallery then show the same engine.
//
// Usage: node check-gallery.cjs <wasm-bindgen --target nodejs out-dir> <gallery.json>
"use strict";
const path = require("node:path");
const fs = require("node:fs");

const [pkgDir, galleryPath] = process.argv.slice(2);
if (!pkgDir || !galleryPath) {
  console.error("usage: node check-gallery.cjs <node-pkg-dir> <gallery.json>");
  process.exit(2);
}
const engine = require(path.resolve(pkgDir, "redactify_web.js"));
const gallery = JSON.parse(fs.readFileSync(galleryPath, "utf8"));

const FIELDS = ["decision", "rationale", "output", "output_is_remask", "entities"];
let failures = 0;
for (const ex of gallery.examples) {
  const live = JSON.parse(engine.analyze(ex.input, ex.locales, ex.target));
  for (const field of FIELDS) {
    const a = JSON.stringify(live[field]);
    const b = JSON.stringify(ex[field]);
    if (a !== b) {
      failures += 1;
      console.error(`MISMATCH ${ex.id}.${field}\n  wasm:   ${a}\n  native: ${b}`);
    }
  }
}
console.log(`${gallery.examples.length} examples checked, ${failures} mismatch(es)`);
process.exit(failures === 0 ? 0 : 1);
