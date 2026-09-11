# Changelog

All notable changes to Rynix MCP are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/).  
Persian mirror: [CHANGELOG.fa.md](CHANGELOG.fa.md)

## [Unreleased]

### Added

- Professional bilingual README (`README.md`, `README.fa.md`) with architecture diagrams
- Project logo assets (`assets/rynix_logo_256.png`) and [docs/LOGO_PROMPT.md](docs/LOGO_PROMPT.md)
- QA gateway: `scripts/run_qa.py`, `scripts/qa.ps1` (ruff, mypy, pylint, pytest, rust, compileall)
- Dev tooling in `mcp-server/pyproject.toml`: ruff, black/isort via ruff, mypy, pylint
- CI workflow runs `run_qa.py` + `final_verify.py` on Linux and Windows
- `CONTRIBUTING.md`, `FAQ.md`, `docs/INDEX.md` (EN + FA variants)

### Changed

- Code formatted with ruff across `mcp-server/` and `scripts/`
- `scripts/run_mcp_30_tool_deep_test.py` — env-only credentials (publish-safe)
- `.github/workflows/rynix-verify.yml` — full QA + DoD gates

### Fixed

- Private path leaks in operator scripts (publish readiness gates G1/G2/G2b)

## [0.1.0] — 2026

### Added

- Initial Rynix MCP platform: 30 MCP tools, Rust `rynix-scan`, Python host
- WSTG 109 knowledge base, 31 technique guides, plugin runtime parity
- 51-stack manifest, example-law-firm profile, 149 pytest tests
- 12 definition-of-done gates via `final_verify.py`

[Unreleased]: https://github.com/YOUR_ORG/rynix-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR_ORG/rynix-mcp/releases/tag/v0.1.0
