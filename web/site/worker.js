// Runs the redactify engine (WebAssembly) off the main thread: the first
// call compiles the rule set, so the page stays responsive meanwhile.
import init, { analyze, supported_locales } from "./pkg/redactify_web.js";

const ready = init();

self.onmessage = async (event) => {
  const { id, text, locales, target } = event.data;
  try {
    await ready;
    if (event.data.kind === "locales") {
      self.postMessage({ id, locales: supported_locales().split(",") });
      return;
    }
    const started = performance.now();
    const result = JSON.parse(analyze(text, locales, target));
    self.postMessage({ id, result, ms: performance.now() - started });
  } catch (err) {
    self.postMessage({ id, error: String(err) });
  }
};
