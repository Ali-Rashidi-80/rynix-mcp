# سؤالات متداول — Rynix MCP

[English](FAQ.md)

---

## عمومی

**معنی «Rynix» چیست؟**  
**Rāy** (رای) = قضاوت / استدلال (عامل IDE). **Nix** = اجرا (ابزار MCP، probe، شواهد).

**آیا Rynix جایگزین عامل IDE می‌شود؟**  
خیر. Rynix **لایه ابزار** است؛ Cursor استدلال LLM را فراهم می‌کند.

**آیا Rynix به API خارجی LLM نیاز دارد؟**  
خیر. عامل IDE مدل خود را دارد؛ Rynix محلی اجرا می‌شود.

---

## راه‌اندازی

**نسخه Python؟**  
۳.۱۲+ (`mcp-server/pyproject.toml`).

**چرا `uv run` برای MCP در ویندوز؟**  
reconnect Cursor ممکن است stdio را بشکند. مسیر `.venv` در `cursor.windows.json` استفاده کنید.

**باینری scanner کجاست؟**  
پس از `build.ps1`: `rynix-core/target/release/rynix-scan.exe`

---

## Engagement

**چگونه live probe فعال کنم؟**  
۱. `RYNIX_TARGET_REPO` را تنظیم کنید.  
۲. `rynix.scope.toml` با `live_probe = true`.  
۳. قبل از probe، `scope_check` را pass کنید.

**گزارش‌ها کجا ذخیره می‌شوند؟**  
`pentest_output/<session_id>/` — gitignore.

---

## امنیت

**چه چیزی commit نشود؟**  
`pentest_output/`، رمز واقعی، JWT، مسیر مطلق ماشین.

**اعتبارسنجی publish:**  
`python scripts\verify_github_publish_ready.py` و `final_verify.py`

---

## عیب‌یابی

| علامت | راه‌حل |
|-------|--------|
| ابزار MCP لیست نمی‌شود | Restart MCP؛ مسیر venv در config |
| `scope_check` deny | `rynix.scope.toml` و `allow_hosts` |
| scanner پیدا نشد | `cargo build --release` در `rynix-core/` |

بیشتر: [docs/ONBOARDING.md](docs/ONBOARDING.md)
