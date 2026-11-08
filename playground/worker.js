// AgentSec playground worker: loads Pyodide and the real invaris-agentsec wheel, then runs attacks.
// It runs in a module Web Worker so the page stays responsive, and so the bring-your-own-key mode
// can use synchronous XMLHttpRequest (allowed in workers) from the synchronous agent function.

const PYODIDE_VERSION = "314.0.7";
const CDN_BASE = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
// A self-hosted copy in ./pyodide/ (same origin) wins over the CDN when present: handy offline
// and for tests. Only a same-origin path is checked, so a link can't point the page elsewhere.
const LOCAL_BASE = new URL("./pyodide/", self.location.href).href;

let pyodide = null;
let ready = null;

function post(msg) {
  self.postMessage(msg);
}

async function exists(url) {
  try {
    const r = await fetch(url, { method: "HEAD", cache: "no-store" });
    return r.ok;
  } catch {
    return false;
  }
}

async function fetchBytes(url, what) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Could not download ${what} (${r.status} ${url}).`);
  return new Uint8Array(await r.arrayBuffer());
}

async function init() {
  post({ type: "status", text: "Downloading Python runtime (Pyodide)…" });
  const base = (await exists(LOCAL_BASE + "pyodide.mjs")) ? LOCAL_BASE : CDN_BASE;
  let mod;
  try {
    mod = await import(base + "pyodide.mjs");
  } catch (e) {
    throw new Error(`Could not load Pyodide from ${base}. Check your connection or ad blocker. (${e})`);
  }
  pyodide = await mod.loadPyodide({ indexURL: base });

  post({ type: "status", text: "Installing PyYAML…" });
  await pyodide.loadPackage("pyyaml");

  post({ type: "status", text: "Installing invaris-agentsec…" });
  const wheel = await fetchBytes(new URL("./vendor/agentsec.whl", self.location.href).href, "the AgentSec package");
  pyodide.unpackArchive(wheel, "wheel");
  const glue = await (await fetch(new URL("./agentsec_playground.py", self.location.href).href)).text();
  pyodide.FS.writeFile("/home/pyodide/agentsec_playground.py", glue);

  const version = pyodide.runPython(`
import sys
sys.path.insert(0, "/home/pyodide")
import agentsec, agentsec_playground
agentsec.__version__
`);
  post({ type: "ready", version, pyodide: PYODIDE_VERSION, source: base === LOCAL_BASE ? "local" : "cdn" });
}

function ensureReady() {
  if (!ready) {
    ready = init().catch((e) => {
      ready = null;
      throw e;
    });
  }
  return ready;
}

self.onmessage = async (event) => {
  const msg = event.data || {};
  const id = msg.id;
  try {
    await ensureReady();
    if (msg.type === "init") return;
    const pg = pyodide.pyimport("agentsec_playground");
    let out;
    if (msg.type === "sample") {
      post({ type: "status", text: "Running attacks…", id });
      out = pg.run_sample(msg.variant === "hardened" ? "hardened" : "naive");
    } else if (msg.type === "llm") {
      post({ type: "status", text: "Running attacks against the model…", id });
      // The key arrives inside this one message, is passed straight to Python, and is dropped
      // when the run ends. It never goes anywhere except the provider's API.
      let config = JSON.stringify(msg.config);
      msg.config = null;
      const progress = (done, total) => post({ type: "progress", done, total, id });
      out = pg.run_llm(config, pg.pyodide_transport, progress);
      config = null;
    } else {
      throw new Error("unknown request " + msg.type);
    }
    pg.destroy();
    post({ type: "result", id, result: JSON.parse(out) });
  } catch (e) {
    post({ type: "fatal", id, message: String((e && e.message) || e) });
  }
};

ensureReady().catch((e) => post({ type: "fatal", message: String((e && e.message) || e) }));
