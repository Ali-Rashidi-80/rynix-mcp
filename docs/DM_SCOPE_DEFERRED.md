# Multi-stack — out of scope (v1)

## Flutter

Flutter mobile/web UI route extraction is **deferred** from v1 D-M scope.

- **Reason:** multi-stack parity achieved via Tier-1 web frontends (React, Next.js, Vue, Nuxt, Angular, SvelteKit).
- **Rynix behavior:** `stack_detect` may hint `flutter` from `pubspec.yaml`; `analyze_repo` falls back to `generic_extractor_used` for Dart route patterns.
- **Gate:** Tier-3 generic listing in `stacks/manifest.toml` — not a dedicated `frontend/flutter.rs` in v1.
- **Future:** dedicated extractor when mobile attack-surface parity is prioritized.

## docker/rynix-tools CLI expansion

**v1 ships 27 generic CLIs** via `scripts/generate_rynix_tools_bin.py` (see `docker/rynix-tools/tools-manifest.toml`).

Gate: `verify_rynix_tools_manifest.py` (minimum 25 tools).
