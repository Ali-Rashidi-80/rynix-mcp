# Rynix MCP — Logo Generation Prompt

Use this prompt with any image model (DALL·E, Midjourney, Stable Diffusion, Cursor GenerateImage, etc.) to reproduce or iterate the project logo.

## Primary 3D Emblem Prompt (Master)

```
Ultra-premium 3D luxury emblem app icon for 'Rynix MCP' - local-first cybersecurity penetration testing platform. A central futuristic 3D heraldic shield forged from matte obsidian titanium and faceted crystal glass. Inside the shield floats a radiant 3D geometric crystal prism emitting brilliant rays of light representing intellect and automated analysis, intertwined with glowing cyan (#00f2fe) and electric amber gold (#ffb300) micro-circuits and precision-machined MCP bus interface pins. Volumetric lighting, exquisite subsurface scattering on the glass edges, metallic bevels, deep ambient occlusion, Cinema4D Octane render aesthetic, isolated on an elegant dark obsidian backdrop (#0b0f17) with a faint micro-mesh grid. High-end modern enterprise cybersecurity branding, crisp edges, perfectly centered, no text.
```

## Flat Vector Alternate Prompt

```
Professional app icon logo for "Rynix MCP" — a local-first security pentest platform.

Design: minimalist flat vector icon, 256×256, dark navy background (#0d1117).

Central motif: stylized shield merged with a neural network node graph —
  • left half: ancient Persian geometric ray pattern (Rāy = reasoning)
  • right half: modern circuit / MCP connector prongs (Nix = execution)

Accent colors: electric cyan (#00d4aa) and amber gold (#f0b429).

Style: clean geometric lines, no text, no gradient overload, subtle inner glow for depth only.
High contrast, crisp edges, enterprise security aesthetic.
Suitable for GitHub README, Cursor MCP config, and favicon downscale.
```

## Variants

| Use case | Aspect | Notes |
|----------|--------|-------|
| README hero | 1:1, 256 px | `assets/rynix_logo_256.png` |
| App icon alias | 1:1, 256 px | `assets/app_icon_256.png` (same asset) |
| Favicon | 1:1, 32–64 px | Export from 256 px master |
| Social banner | 16:9 | Widen shield; add subtle grid background |

## Brand semantics

| Element | Meaning |
|---------|---------|
| **Rynix** | Rāy (رای, judgment/reasoning) + Nix (execution, MCP tools) |
| **Shield** | Defensive security, evidence-first auditing |
| **Ray pattern** | Host agent reasoning (Cursor / IDE) |
| **MCP prongs** | Tool execution layer — no external LLM API keys |
| **Cyan** | Active probes, live signals |
| **Gold** | Verified findings, SARIF evidence |

## Files in repo

- `assets/rynix_logo_256.png` — canonical logo
- `assets/app_icon_256.png` — alias for README / docs

Do not embed machine-specific paths or private org names in generated assets.
