<div align="center">

[English](README.md) · **فارسی**

<img src="assets/rynix_logo_256.png" alt="لوگوی Rynix MCP" width="128" height="128" />

# Rynix MCP

> **Rynix: Where ancient reasoning meets modern execution.**  
> *(جایی که استدلال باستانی با اجرای مدرن تلاقی می‌کند.)*

**پلتفرم امنیتی MCP محلی‌اول — تحلیلگر استاتیک Rust (`rynix-scan`) + میزبان Python (`rynix-mcp`).**

[![مجوز: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](mcp-server/pyproject.toml)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](rynix-core/Cargo.toml)
[![ابزار MCP](https://img.shields.io/badge/MCP%20tools-30-cyan.svg)](#ابزارهای-mcp-۳۰)
[![تست‌ها](https://img.shields.io/badge/tests-149%20passing-brightgreen.svg)](#اجرای-تست‌ها)
[![WSTG](https://img.shields.io/badge/WSTG-109%20tests-purple.svg)](#پایگاه-دانش)

- **Rāy (رای):** استدلال عامل Cursor / IDE
- **Nix:** ابزارهای MCP، پروب، گزارش — **بدون کلید API خارجی LLM**

</div>

---

## فهرست مطالب

<details open>
<summary><strong>پرش به بخش</strong></summary>

- [Rynix MCP چیست؟](#rynix-mcp-چیست)
- [چرا استفاده کنیم؟](#چرا-استفاده-کنیم)
- [معماری](#معماری)
- [ابزارهای MCP (۳۰)](#ابزارهای-mcp-۳۰)
- [شروع سریع](#شروع-سریع)
- [پیکربندی Cursor MCP](#پیکربندی-cursor-mcp)
- [جریان کار اپلیکیشن هدف](#جریان-کار-اپلیکیشن-هدف)
- [پلاگین‌ها (تعادل runtime)](#پلاگین‌ها-تعادل-runtime)
- [پایگاه دانش](#پایگاه-دانش)
- [پروفایل‌ها و چند-استک](#پروفایل‌ها-و-چند-استک)
- [اعتبارسنجی و QA](#اعتبارسنجی-و-qa)
- [ساختار پروژه](#ساختار-پروژه)
- [متغیرهای محیطی](#متغیرهای-محیطی)
- [محدودیت‌های صادقانه](#محدودیت‌های-صادقانه)
- [سؤالات متداول](#سؤالات-متداول)
- [فهرست مستندات](#فهرست-مستندات)
- [مشارکت](#مشارکت)
- [مجوز](#مجوز)

</details>

---

## Rynix MCP چیست؟

**Rynix MCP** یک **پلتفرم امنیتی محلی‌اول** است که از طریق [Model Context Protocol](https://modelcontextprotocol.io/) به IDE شما (Cursor، Claude Desktop و غیره) متصل می‌شود. عامل میزبان استدلال می‌کند؛ Rynix اجرا می‌کند:

| لایه | جزء | نقش |
|------|-----|-----|
| **استاتیک** | `rynix-scan` (Rust) | استخراج مسیر، RBAC، الگوی secret، taint sink |
| **فعال** | `rynix-mcp` (Python) | پروب HTTP محدود، ماتریس IDOR دو-توکن، auth، خروجی SARIF |
| **دانش** | playbookهای بسته‌بندی‌شده | WSTG ۱۰۹ · راهنمای تکنیک · کاتالوگ vuln-class |
| **پلاگین** | sidecar runnerها | ارکستراتور WSTG، engagement guard، agent guides |

```text
+------------------+       MCP (stdio)        +---------------------------+
|  عامل میزبان     | <----------------------> |  rynix-mcp (Python)       |
|  (Cursor / IDE)  |   ۳۰ ابزار + playbook   |  session · probe · SARIF  |
+------------------+                          +-------------+-------------+
                                                            |
                                                            v
                                              +-------------+-------------+
                                              |  rynix-scan (Rust)        |
                                              |  باینری تحلیل استاتیک     |
                                              +---------------------------+
```

> [!NOTE]
> Rynix **API خارجی LLM** فراخوانی نمی‌کند. عامل IDE شما استدلال می‌کند؛ Rynix ابزار، شواهد و guardrail می‌دهد.

---

## چرا استفاده کنیم؟

| مشکل | راه‌حل Rynix |
|------|--------------|
| یادداشت‌های pentest پراکنده در چت‌ها | findingهای session-scoped، audit log، `export_report` |
| تست IDOR دستی و کند | `run_idor_matrix` — مقایسه dual-token با جفت نقش profile-aware |
| استاتیک و داینامیک جدا | `analyze_repo` → `generate_pentest_brief` → live probe در یک session |
| scope creep روی target زنده | `scope_check` پیش‌فرض deny + `rynix.scope.toml` |
| قفل vendor روی اسکنر ابری | کاملاً محلی؛ credential فقط از env؛ مجوز MIT |
| نیاز عامل به عمق متدولوژی | WSTG ۱۰۹ + ۳۱ راهنمای تکنیک + playbook engagement |
| repo چند-framework | ۵۱ stack در `stacks/manifest.toml` |

---

## معماری

**اصول طراحی** (جزئیات: [docs/MCP_DESIGN.md](docs/MCP_DESIGN.md)):

1. **scope پیش‌فرض deny** — `scope_check` قبل از هر live probe.
2. **شواهد session** — findingها با `session_id`؛ export به `pentest_output/`.
3. **تعادل پلاگین** — sidecarها در همان session + SARIF ادغام می‌شوند.
4. **Agent-native** — بدون LLM دوم؛ [docs/AGENT_NATIVE.md](docs/AGENT_NATIVE.md).

---

## ابزارهای MCP (۳۰)

| گروه | ابزارها |
|------|---------|
| **استاتیک (۸)** | `analyze_repo`, `list_api_routes`, `list_frontend_routes`, `rbac_matrix`, `high_risk_surfaces`, `generate_pentest_brief`, `list_profiles`, `health_check` |
| **فعال (۱۰)** | `scope_check`, `http_probe`, `auth_login`, `unlock_stealth_gate`, `check_access`, `compare_role_response`, `record_finding`, `export_report`, `export_openapi_stub`, **`run_idor_matrix`** |
| **Engagement (۶)** | `register_scope`, `track_wstg_test`, `track_probe_step`, `save_engagement_context`, `get_engagement_context`, `list_engagement_progress` |
| **دانش (۲)** | `get_technique_guide`, `get_wstg_test` |
| **Playbook (۱)** | `agent_engagement_playbook` |
| **پلاگین (۳)** | `list_plugins`, `plugin_health_check`, `rynix_plugin_run` |

**جریان engagement معمول:**

```text
health_check → analyze_repo → generate_pentest_brief
→ register_scope → scope_check → agent_engagement_playbook
→ auth_login → run_idor_matrix(allow_live=true)
→ record_finding(verified=True) → export_report
```

---

## شروع سریع

```powershell
git clone <your-fork>/rynix-mcp.git
cd rynix-mcp
.\scripts\build.ps1
.\scripts\verify.ps1
```

اسکنر template اختیاری (CVE):

```powershell
.\scripts\install-template-scan.ps1
# سپس در env MCP: "RYNIX_TEMPLATE_SCAN_BIN": "${workspaceFolder}/bin/template-scan"
```

---

## پیکربندی Cursor MCP

از `cursor.posix.json` (macOS/Linux) یا `cursor.windows.json` (Windows) استفاده کنید — هر دو `${workspaceFolder}` دارند (بدون مسیر ماشین‌خاص).

`cursor-mcp.example.json` را به تنظیمات MCP کاربر کپی کنید.

پس از تغییر کد: `.\scripts\build.ps1` سپس **Restart** MCP در Cursor.

---

## جریان کار اپلیکیشن هدف

فایل‌های per-repo در **اپلیکیشن شما** (نه در rynix-mcp):

- `rynix.scope.toml` — `live_probe=false` تا `allow_live=true` روی probeها
- `.pentest/profile.toml` — override scope/brief/profile

```text
health_check → analyze_repo → generate_pentest_brief
scope_check → run_idor_matrix(base_url="http://127.0.0.1:8001", allow_live=true, session_id="audit-1")
export_report → pentest_output/.../evidence/
```

اعتبارنامه فقط از env (هرگز commit نکنید):

```powershell
$env:RYNIX_TARGET_REPO="C:\path\to\your-app"
$env:RYNIX_PROFILE="example-law-firm"
$env:RYNIX_PROBE_PASSWORD="..."
$env:RYNIX_PROBE_BASE_URL="http://127.0.0.1:8001"
uv run --directory mcp-server python ..\scripts\live_idor_matrix.py
```

---

## پلاگین‌ها (تعادل runtime)

| پلاگین | استراتژی | وضعیت |
|--------|----------|--------|
| `template-scan` | binary wrap | CVE templates (نیاز `RYNIX_TEMPLATE_SCAN_BIN`) |
| `wstg` | native + docker | چک‌لیست WSTG ۱۰۹ |
| `engagement` | Rynix-native | scope guard، validate، scopes |
| `sarif-import` | native | ادغام SARIF در session |
| `agent-guides` | host-agent | راهنمای تکنیک + playbook |
| `pipeline-runner` | host-agent | مراحل recon→analyze→exploit→report |
| `cyber-range` | host-agent | سناریو bench + trajectory log |
| `whitebox-scan` | host-agent | صف استاتیک → اعتبارسنجی exploit |
| `agent-orchestrator` | host-agent | پیش‌فرض غیرفعال |
| `browser-debug` | host-agent | پیش‌فرض غیرفعال |

```text
rynix_plugin_run("engagement", options='{"action":"check","url":"http://127.0.0.1:8001"}')
rynix_plugin_run("engagement", options='{"action":"scopes"}')
rynix_plugin_run("agent-guides", options='{"action":"playbook","scan_mode":"quick"}')
```

---

## پایگاه دانش

بسته‌بندی‌شده در `mcp-server/rynix_mcp/knowledge/`:

| کاتالوگ | تعداد | توضیح |
|---------|-------|-------|
| **WSTG** | ۱۰۹ تست | چک‌لیست کامل OWASP WSTG |
| **Techniques** | ۳۱+ موضوع | منبع ترجیحی برای موضوعات overlapping |
| **Vuln classes** | ۷۵+ راهنما | متدولوژی agent-guides درون‌درختی |
| **Frameworks** | ۵۱ stack | deepdive در `knowledge/frameworks/` |

WSTG ۱۰۹ · technique ۳۱ · کاتالوگ vuln-classes (technique برای موضوعات overlapping ترجیح دارد)

---

## پروفایل‌ها و چند-استک

- `profiles/generic-fastapi-react.toml`
- `profiles/example-law-firm.toml`
- `examples/example-law-firm/engagement-mirror.yaml`

**تشخیص چند-استک:** `stack_detect.py` + `stacks/manifest.toml` — **۵۱ framework** با extractor Tier-1.

---

## اعتبارسنجی و QA

```powershell
.\scripts\verify.ps1          # G1–G9
python scripts\run_contract.py
python scripts\final_verify.py
python scripts\mcp_self_audit.py
```

**QA کامل:**

```powershell
.\scripts\qa.ps1              # ruff + mypy + pylint + pytest + rust + final_verify
```

**CI:** `.github/workflows/rynix-verify.yml` — Linux و Windows.

---

## ساختار پروژه

```text
rynix-mcp/
├── assets/                 # لوگو
├── docs/                   # معماری، onboarding، publishing
├── mcp-server/rynix_mcp/   # بسته MCP (۳۰ ابزار)
├── rynix-core/             # تحلیلگر Rust
├── plugins/ profiles/ stacks/
└── scripts/                # build، verify، QA
```

---

## متغیرهای محیطی

| متغیر | هدف |
|-------|-----|
| `RYNIX_TARGET_REPO` | مسیر repo اپلیکیشن |
| `RYNIX_PROFILE` | پروفایل پیش‌فرض |
| `RYNIX_PROBE_PASSWORD` | رمز کاربر تست |
| `RYNIX_PROBE_BASE_URL` | URL پایه target |

جدول کامل: [docs/GITHUB_PUBLISHING.md](docs/GITHUB_PUBLISHING.md)

---

## محدودیت‌های صادقانه

| موضوع | واقعیت |
|-------|--------|
| Live probe | نیاز `allow_live=true` + host در scope |
| مرورگر | پلاگین `browser-debug` پیش‌فرض غیرفعال |
| CVE template | نیاز نصب باینری جدا |
| Production | mirror محلی / staging ترجیح داده می‌شود |
| LLM | فقط از عامل IDE شما — Rynix شامل LLM نیست |

---

## سؤالات متداول

**آیا Rynix کد را به ابر می‌فرستد؟**  
خیر. تحلیل و probe محلی است.

**گزارش‌ها کجا ذخیره می‌شوند؟**  
`pentest_output/<session_id>/` — پیش‌فرض gitignore.

بیشتر: [docs/FAQ.fa.md](docs/FAQ.fa.md)

---

## فهرست مستندات

| سند | توضیح |
|-----|-------|
| [README.md](README.md) | README انگلیسی |
| [docs/ONBOARDING.md](docs/ONBOARDING.md) | راهنمای اولین engagement |
| [docs/INDEX.fa.md](docs/INDEX.fa.md) | فهرست کامل فارسی |
| [CONTRIBUTING.fa.md](CONTRIBUTING.fa.md) | راهنمای مشارکت |

---

## مشارکت

[CONTRIBUTING.fa.md](CONTRIBUTING.fa.md) — قبل از PR: `.\scripts\qa.ps1`

---

## مجوز

MIT — [LICENSE](LICENSE)
