# Contributing to Rynix MCP

[Persian / فارسی](CONTRIBUTING.fa.md)

Thank you for considering a contribution. Rynix welcomes bug reports, documentation improvements, and tested feature PRs.

---

## Ways to contribute

| Type | How |
|------|-----|
| Bug report | Open an issue with repro steps + `session_id` / gate output |
| Feature idea | Open an issue describing the pentest workflow first |
| Documentation | PRs to `README.md`, `docs/`, or `README.fa.md` |
| Code | Fork → branch → PR with tests |

---

## Development setup

```powershell
git clone https://github.com/YOUR_ORG/rynix-mcp.git
cd rynix-mcp
.\scripts\build.ps1
.\scripts\qa.ps1
```

Requirements: **Python 3.12+**, **Rust stable**, **uv**.

---

## Code guidelines

1. **Match existing style** — type hints, `pathlib`, env-based credentials.
2. **Minimal scope** — one logical change per PR.
3. **No private paths** — never commit real passwords, JWTs, or `D:\...` machine paths.
4. **Tests required** for MCP tools, probes, and export logic:

```powershell
cd mcp-server
.\.venv\Scripts\python.exe -m pytest -q
```

5. **Documentation** — update EN docs first; mirror critical changes in `.fa.md` files.
6. **Publish gates** — must pass before merge:

```powershell
python scripts\verify_github_publish_ready.py
python scripts\final_verify.py
```

---

## QA before PR

```powershell
.\scripts\qa.ps1
```

Runs: ruff · mypy · pylint · pytest (149) · cargo test · compileall · final_verify gates.

---

## Pull request checklist

- [ ] `run_qa.py` passes locally
- [ ] `final_verify.py` passes
- [ ] No private leaks (`verify_no_private_leaks.py`)
- [ ] README tool count matches `server.py` if tools changed
- [ ] EN + FA docs updated when user-facing behavior changes

---

## License

Contributions are licensed under the project MIT license.
