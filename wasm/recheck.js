// Browser glue for recheck.wasm.
//
//   <script src="wasm_exec.js"></script>
//   <script type="module">
//     import { loadRecheck } from "./recheck.js";
//     const recheck = await loadRecheck("./recheck.wasm");
//     const report = JSON.parse(recheck.verify(receiptText));           // the --json report
//     const diff = JSON.parse(recheck.tamper(receiptText, editedText)); // first differing byte
//   </script>
//
// loadRecheck fetches exactly one URL — the wasm it is given — and resolves with
// window.recheck = { version, verify(receiptJson, opts?), tamper(original, edited) }, where opts
// may carry keys, root and proof as the text of those files. Neither this file nor the module
// makes any other request: verify runs entirely in memory, so a page can count its requests and
// see one. wasm_exec.js is the Go runtime shim shipped next to the module; it defines Go and must
// be loaded first, which is why this file does not fetch it for you.

const root = globalThis;
let loading = null;

export function loadRecheck(wasmUrl) {
  if (root.recheck && typeof root.recheck.verify === "function") return Promise.resolve(root.recheck);
  if (loading) return loading;
  loading = start(wasmUrl).catch((err) => {
    loading = null;
    throw err;
  });
  return loading;
}

async function start(wasmUrl) {
  if (typeof wasmUrl !== "string" || wasmUrl === "") throw new TypeError("loadRecheck(wasmUrl): pass the URL of recheck.wasm");
  if (typeof root.Go !== "function") throw new Error("loadRecheck: load wasm_exec.js (shipped next to recheck.wasm) before recheck.js");
  if (typeof WebAssembly !== "object") throw new Error("loadRecheck: this browser has no WebAssembly");

  const go = new root.Go();
  const ready = new Promise((resolve) => {
    root.__recheckReady = (api) => {
      delete root.__recheckReady;
      resolve(api);
    };
  });

  const response = await fetch(wasmUrl, { credentials: "same-origin" });
  if (!response.ok) throw new Error(`loadRecheck: fetching ${wasmUrl} answered http ${response.status}`);
  const type = (response.headers.get("content-type") || "").split(";")[0].trim();
  const { instance } =
    typeof WebAssembly.instantiateStreaming === "function" && type === "application/wasm"
      ? await WebAssembly.instantiateStreaming(response, go.importObject)
      : await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject);

  // The module installs window.recheck while starting up and then parks; go.run only settles if
  // it exits instead, which is the failure case.
  const exited = go.run(instance).then(() => {
    throw new Error("loadRecheck: recheck.wasm exited before installing its API");
  });
  return Promise.race([ready, exited]);
}

export default loadRecheck;
root.loadRecheck = loadRecheck;
