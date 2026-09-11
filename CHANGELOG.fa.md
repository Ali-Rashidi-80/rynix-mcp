# تاریخچه تغییرات

نسخه فارسی — نسخه اصلی: [CHANGELOG.md](CHANGELOG.md)

## [منتشرنشده]

### افزوده‌شده

- README دوزبانه حرفه‌ای با دیاگرام معماری
- لوگو (`assets/rynix_logo_256.png`) و [docs/LOGO_PROMPT.md](docs/LOGO_PROMPT.md)
- دروازه QA: `scripts/run_qa.py`، `scripts/qa.ps1`
- ابزارهای dev: ruff، mypy، pylint در `pyproject.toml`
- CI: `run_qa.py` + `final_verify.py` روی Linux و Windows
- `CONTRIBUTING`، `FAQ`، `docs/INDEX` (EN + FA)

### تغییر

- فرمت ruff در `mcp-server/` و `scripts/`
- اسکریپت deep test — credential فقط از env

### رفع

- نشت مسیر خصوصی در gateهای publish

## [0.1.0] — ۲۰۲۶

- پلتفرم اولیه: ۳۰ ابزار MCP، `rynix-scan`، میزبان Python
- WSTG ۱۰۹، ۱۴۹ تست pytest، ۱۲ gate DoD
