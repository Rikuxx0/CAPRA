# Repository Guidelines

## Project Structure & Module Organization
`app.py` is the Streamlit entrypoint for CAPRA. Layer 1 parsing, schema, graph, and export logic lives under `capra/layer1/`; Layer 2 attack-operator modeling lives under `capra/layer2/`. Repository-level assets include [README.md](/Users/rikuxx/CAPRA/README.md), `examples/`, and `demo.mp4`. Keep reusable logic in the appropriate layer rather than expanding `app.py`.

## Build, Test, and Development Commands
Install dependencies with `pip install -r requirements.txt`. Run the app locally with `streamlit run app.py`. For quick syntax validation, use `python -m py_compile app.py capra/layer1/*.py capra/layer1/parsers/*.py capra/layer1/utils/*.py`. If you add third-party packages or new setup steps, update `README.md` in the same change.

## Coding Style & Naming Conventions
Follow PEP 8 with 4-space indentation and `snake_case` for functions, variables, and module names. Keep Streamlit UI text in `app.py`; keep parsing, scoring, graph, and export logic in small helper functions under `capra/layer1/`. Prefer explicit dictionary keys only when matching existing data contracts. Add short comments only where the control flow or parsing rule is not obvious from the code.

## Testing Guidelines
There is no dedicated `tests/` directory yet, so contributors should add targeted tests for new parsing or graph logic. Prefer `pytest`, with files named `tests/test_<module>.py`. At minimum, validate:
- Grype JSON/SARIF parsing with representative fixtures
- CVE-to-node mapping behavior
- attack path generation for a small Draw.io sample

Run `pytest` once tests exist, and keep sample inputs small enough to review in the repository.

## Commit & Pull Request Guidelines
Recent history mixes concise English subjects and generic Japanese messages such as `変更`; use clearer imperative subjects going forward, for example `Add Grype severity normalization`. Keep commits focused on one change. PRs should include a short problem statement, the main implementation notes, local verification steps, and screenshots for Streamlit UI changes. Link the related issue or task when one exists.

## Security & Configuration Tips
Never commit API keys, report data with secrets, or large temporary analysis outputs. Sanitize vulnerability samples before adding them as fixtures or documentation examples.

## Layer 2 Safety and Reproducibility
Layer 2 is deterministic, rule-based modeling: do not use an LLM, execute attacks, validate a live target, or fetch/store exploit code. Keep Hound semantics isolated by adapter; IAMHoundDog uses bounded multi-edge patterns, while direct attack edges are converted only by their source-specific adapter. Preserve fact provenance and unresolved data, generate stable IDs from canonical inputs, and recursively redact secrets/tokens from evidence, output, and logs. Runtime validation belongs to Layer 3.
