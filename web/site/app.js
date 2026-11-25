// Demo page logic. Text from the user and from the engine is only ever
// written with textContent (never innerHTML), so no input can become markup.

const $ = (id) => document.getElementById(id);
const DEFAULT_LOCALES = ["tr", "en"];

// ---------------------------------------------------------------- engine
// The worker (and the ~0.9 MB compressed engine) loads on first use, not on
// page load.
let worker = null;
let nextId = 0;
const pending = new Map();

function engine() {
  if (!worker) {
    worker = new Worker("worker.js", { type: "module" });
    worker.onmessage = (event) => {
      const done = pending.get(event.data.id);
      if (done) {
        pending.delete(event.data.id);
        done(event.data);
      }
    };
    worker.onerror = () => setStatus("The engine could not start in this browser.");
  }
  return worker;
}

function call(message) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    engine().postMessage({ ...message, id });
  });
}

// ---------------------------------------------------------------- demo
function setStatus(text) {
  $("status").textContent = text;
}

// The chosen locale packs live here, not in the checkboxes: the list is
// rendered only once the engine is loaded, but an example's locales must
// apply before that too.
let chosenLocales = [...DEFAULT_LOCALES];

function setLocales(codes) {
  chosenLocales = [...codes];
  document.querySelectorAll("#locale-list input").forEach((box) => {
    box.checked = chosenLocales.includes(box.value);
  });
  updateLocaleSummary();
}

function renderLocales(codes) {
  const list = $("locale-list");
  for (const code of codes) {
    const label = document.createElement("label");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.value = code;
    box.checked = chosenLocales.includes(code);
    box.addEventListener("change", () => {
      chosenLocales = [...document.querySelectorAll("#locale-list input:checked")].map((i) => i.value);
      updateLocaleSummary();
      schedule();
    });
    label.append(box, " " + code);
    list.append(label);
  }
}

function updateLocaleSummary() {
  $("locale-summary").textContent = `(${chosenLocales.length ? chosenLocales.join(", ") : "default: tr, en"})`;
}

function renderResult(result, input) {
  $("result").hidden = false;
  const badge = $("decision");
  badge.className = `badge ${result.decision}`;
  const icon = { Allow: "✓", Log: "ℹ", Mask: "■", Block: "✕" }[result.decision] || "";
  badge.textContent = `${icon} ${result.decision}`;
  $("rationale").textContent = result.rationale;
  $("output").textContent = result.output;
  $("remask-note").hidden = !result.output_is_remask;
  const list = $("entities");
  list.replaceChildren();
  if (result.entities.length === 0) {
    const li = document.createElement("li");
    li.textContent = "none";
    list.append(li);
  }
  for (const e of result.entities) {
    const li = document.createElement("li");
    const mark = document.createElement("mark");
    // offsets are UTF-16 code units, the unit of String.prototype.slice
    mark.textContent = input.slice(e.start_utf16, e.end_utf16);
    li.append(`${e.kind} `, mark, ` (${e.score.toFixed(2)})`);
    list.append(li);
  }
}

let running = false;
let rerun = false;
async function run() {
  if (running) {
    rerun = true;
    return;
  }
  running = true;
  const input = $("input").value;
  setStatus(worker ? "Analyzing…" : "Loading the engine…");
  const reply = await call({
    kind: "analyze",
    text: input,
    locales: chosenLocales.join(","),
    target: $("target").value,
  });
  running = false;
  if (reply.error) {
    setStatus(`Error: ${reply.error}`);
  } else {
    renderResult(reply.result, input);
    setStatus(`Analyzed in ${reply.ms.toFixed(1)} ms, in this browser.`);
  }
  if (rerun) {
    rerun = false;
    run();
  }
}

let timer = 0;
function schedule() {
  if (!worker) return; // typing alone does not download the engine
  clearTimeout(timer);
  timer = setTimeout(run, 250);
}

// ---------------------------------------------------------------- gallery
function renderGallery(examples) {
  const groups = [...new Set(examples.map((e) => e.group))];
  const tabs = $("tabs");
  const panels = $("panels");
  groups.forEach((group, i) => {
    const tab = document.createElement("button");
    tab.type = "button";
    tab.setAttribute("role", "tab");
    tab.id = `tab-${i}`;
    tab.setAttribute("aria-controls", `panel-${i}`);
    tab.setAttribute("aria-selected", String(i === 0));
    tab.tabIndex = i === 0 ? 0 : -1;
    tab.textContent = group;
    tab.addEventListener("click", () => selectTab(i));
    tab.addEventListener("keydown", (event) => {
      const n = groups.length;
      const to = { ArrowRight: (i + 1) % n, ArrowLeft: (i - 1 + n) % n, Home: 0, End: n - 1 }[event.key];
      if (to !== undefined) {
        event.preventDefault();
        selectTab(to);
        $(`tab-${to}`).focus();
      }
    });
    tabs.append(tab);

    const panel = document.createElement("div");
    panel.setAttribute("role", "tabpanel");
    panel.id = `panel-${i}`;
    panel.setAttribute("aria-labelledby", tab.id);
    panel.hidden = i !== 0;
    for (const ex of examples.filter((e) => e.group === group)) {
      panel.append(renderExample(ex));
    }
    panels.append(panel);
  });
}

function selectTab(index) {
  document.querySelectorAll('[role="tab"]').forEach((tab, i) => {
    tab.setAttribute("aria-selected", String(i === index));
    tab.tabIndex = i === index ? 0 : -1;
  });
  document.querySelectorAll('[role="tabpanel"]').forEach((panel, i) => {
    panel.hidden = i !== index;
  });
}

function renderExample(ex) {
  const box = document.createElement("article");
  box.className = "example";
  const title = document.createElement("h3");
  title.textContent = ex.title;
  const io = document.createElement("div");
  io.className = "io";
  const column = (label, text) => {
    const div = document.createElement("div");
    const span = document.createElement("div");
    span.className = "label";
    span.textContent = label;
    const pre = document.createElement("pre");
    pre.className = "output";
    pre.textContent = text;
    div.append(span, pre);
    return div;
  };
  const scope = [ex.locales && `locales: ${ex.locales}`, ex.target !== "user_prompt" && `target: ${ex.target}`]
    .filter(Boolean)
    .join(", ");
  io.append(
    column(scope ? `Input (${scope})` : "Input", ex.input),
    column(`Output — ${ex.decision}${ex.output_is_remask ? " (loggable re-mask)" : ""}`, ex.output),
  );
  const tryIt = document.createElement("button");
  tryIt.type = "button";
  tryIt.className = "try";
  tryIt.textContent = "Try it";
  tryIt.addEventListener("click", () => {
    $("input").value = ex.input;
    $("target").value = ex.target;
    setLocales(ex.locales ? ex.locales.split(",") : DEFAULT_LOCALES);
    $("demo-title").scrollIntoView({ block: "start" });
    run();
  });
  box.append(title, io, tryIt);
  return box;
}

// ---------------------------------------------------------------- copy buttons
// Every [data-copy] block gets a button that copies its code text.
const SVG_NS = "http://www.w3.org/2000/svg";
const ICON_COPY = ["M9 9h10v10H9z", "M5 15V5h10"];
const ICON_DONE = ["M5 12l5 5L19 7"];

function setIcon(button, paths) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const d of paths) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  button.querySelector("svg")?.remove();
  button.prepend(svg);
}

function flash(button, text, ok) {
  button.querySelector(".copy-tip")?.remove();
  const tip = document.createElement("span");
  tip.className = "copy-tip";
  tip.setAttribute("role", "status");
  tip.textContent = text;
  button.append(tip);
  button.classList.toggle("done", ok);
  if (ok) setIcon(button, ICON_DONE);
  clearTimeout(button.resetTimer);
  button.resetTimer = setTimeout(() => {
    tip.remove();
    button.classList.remove("done");
    setIcon(button, ICON_COPY);
  }, 1600);
}

function selectText(node) {
  const range = document.createRange();
  range.selectNodeContents(node);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

for (const block of document.querySelectorAll("[data-copy]")) {
  const source = block.querySelector("pre, code");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy";
  button.setAttribute("aria-label", "Copy to clipboard");
  button.title = "Copy";
  setIcon(button, ICON_COPY);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(source.textContent);
      flash(button, "Copied", true);
    } catch {
      // no clipboard access (insecure context, denied): select for Ctrl+C
      selectText(source);
      flash(button, "Press Ctrl+C", false);
    }
  });
  block.append(button);
}

// ---------------------------------------------------------------- start
$("run").addEventListener("click", run);
$("input").addEventListener("input", schedule);
$("target").addEventListener("change", schedule);

// the locale list comes from the engine; until it loads, show the default
// codes (the engine is loaded only when the reader opens the list or runs)
const localeList = document.querySelector(".locales");
localeList.addEventListener("toggle", async () => {
  if (localeList.open && $("locale-list").children.length <= 1) {
    const reply = await call({ kind: "locales" });
    if (reply.locales) renderLocales(reply.locales);
  }
}, { once: false });

fetch("gallery.json")
  .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.statusText))))
  .then((doc) => renderGallery(doc.examples))
  .catch(() => {
    $("panels").textContent = "The examples could not be loaded.";
  });
