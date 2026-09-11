# مشارکت در Rynix MCP

[English](CONTRIBUTING.md)

از مشارکت شما سپاسگزاریم. Rynix گزارش bug، بهبود مستندات و PRهای تست‌شده را می‌پذیرد.

---

## روش‌های مشارکت

| نوع | چگونه |
|-----|-------|
| گزارش bug | issue با مراحل repro + خروجی gate |
| ایده feature | issue با توضیح workflow pentest |
| مستندات | PR به `README.md`، `docs/`، `README.fa.md` |
| کد | Fork → branch → PR با تست |

---

## راه‌اندازی توسعه

```powershell
git clone https://github.com/YOUR_ORG/rynix-mcp.git
cd rynix-mcp
.\scripts\build.ps1
.\scripts\qa.ps1
```

نیازمندی‌ها: **Python 3.12+**، **Rust stable**، **uv**.

---

## دستورالعمل کد

1. **سبک موجود** — type hint، `pathlib`، credential از env.
2. **دامنه کم** — یک تغییر منطقی در هر PR.
3. **بدون مسیر خصوصی** — هرگز رمز واقعی یا مسیر ماشین commit نکنید.
4. **تست الزامی** برای ابزار MCP، probe و export.
5. **مستندات** — ابتدا EN؛ سپس `.fa.md` برای تغییرات مهم.

---

## QA قبل از PR

```powershell
.\scripts\qa.ps1
```

شامل: ruff · mypy · pylint · pytest · cargo · compileall · final_verify.

---

## چک‌لیست PR

- [ ] `run_qa.py` محلی pass
- [ ] `final_verify.py` pass
- [ ] بدون نشت خصوصی
- [ ] README با تعداد ابزارها هم‌خوان (در صورت تغییر tool)
- [ ] مستندات EN + FA به‌روز

---

## مجوز

مشارکت‌ها تحت مجوز MIT پروژه است.
