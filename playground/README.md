# AgentSec Playground

A static page that runs the real `invaris-agentsec` package in the browser with
[Pyodide](https://pyodide.org) inside a Web Worker. No backend: GitHub Pages serves the files,
and every attack runs on the visitor's machine.

Live: https://invarislabs.github.io/invaris-agentsec/

## Modes

- **Sample agent (no key).** The agent from `examples/notebooks/agentsec_quickstart.ipynb`. Every
  category runs. The naive version gets 8 critical findings; the hardened version gets 0.
- **Your model (bring your own key).** The setup from `examples/notebooks/agentsec_real_llm.ipynb`:
  the notebook's system prompt and tools, five categories (about 22 scenarios), and an optional guard
  in code. Providers: OpenAI, Groq, OpenRouter, Anthropic (Messages API, sent with
  `anthropic-dangerous-direct-browser-access`), or any OpenAI-compatible base URL (`https://`, or
  `http://localhost` for a local model server).

The key is held in memory for one run. It's passed to the worker, used for the provider request
and then dropped. It is never written to storage and never sent anywhere except the chosen
provider. Only the provider, model and base URL are remembered (localStorage).

## How it works

| File | Role |
| --- | --- |
| `index.html`, `styles.css`, `app.js` | UI. Report text is inserted with `textContent` only, since attack inputs are adversarial by design. |
| `worker.js` | Loads Pyodide (jsDelivr, or `./pyodide/` if you self-host it), PyYAML, and `vendor/agentsec.whl`. |
| `agentsec_playground.py` | Python run in Pyodide: the sample agents, the LLM agent and provider error handling, and conversion of a result to JSON (it reuses the engine's `build_report` and `render_markdown`). Tested in `tests/test_playground.py`. |
| `build.sh` | Builds the wheel from this checkout into `vendor/agentsec.whl`. The page always runs the repo's code, not the last PyPI release. |
| `e2e/` | Playwright browser test, with a mock provider for bring-your-own-key mode. |

The engine's `CallableAdapter` calls the agent synchronously. In bring-your-own-key mode the agent
makes its provider request with synchronous `XMLHttpRequest`, which browsers allow in workers. That
is why everything runs in a worker, and why no engine changes were needed. After a fatal error
(401/403, CORS block, 404, 429, or a 400 on the first request) the agent stops calling the provider.

Whether a provider accepts calls from a web page (CORS) is up to the provider. When one doesn't, the
page says so and points to the notebook or `pip install invaris-agentsec`.

## Run locally

```bash
bash playground/build.sh                     # builds vendor/agentsec.whl
python -m http.server -d playground 8000     # then open http://localhost:8000
```

Browser test (Chromium):

```bash
pip install pytest playwright && python -m playwright install chromium
pytest playground/e2e -v                     # E2E_SCREENSHOTS=shots/ to save screenshots
```

To run offline, copy Pyodide's core files (`pyodide.mjs`, `pyodide.asm.mjs`, `pyodide.asm.wasm`,
`python_stdlib.zip`, `pyodide-lock.json`) and its PyYAML wheel into `playground/pyodide/`
(gitignored). The worker uses that copy instead of the CDN.

## Deploy

`.github/workflows/playground.yml` runs the playground tests, builds the wheel and deploys to GitHub
Pages on pushes to `main` that touch `playground/`, `agentsec/` or `pyproject.toml`. One-time
setup: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
