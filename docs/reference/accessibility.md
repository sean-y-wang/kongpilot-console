# Readability and contrast (WCAG 2.1 AA)

Target: normal text ≥ 4.5:1, large text (≥ 18.66px bold / 24px) and icons ≥ 3:1,
measured against `canvas`, `panel` and `soft` surfaces in both appearances.
Tokens live in `packages/contracts/src/pilot-theme.ts` (antd) and
`packages/contracts/src/pilot-appearance.css` (`--kp-*`). Portal and console
stylesheets must use `var(--kp-*)` for text instead of hardcoded greys.

| Token (light) | Before | Ratio on canvas/white | After | Ratio on canvas/white |
|---|---|---|---|---|
| body | #4E5969 | 6.68 / 7.10 | #3D4756 | 8.85 / 9.40 |
| muted / secondary | #86909C | 3.05 / 3.24 ❌ | #5C6675 | 5.47 / 5.81 |
| primary / link | #59668D | 5.33 / 5.66 | #4F5C83 | 6.19 / 6.58 |
| success | #278564 | 4.27 ❌ / 4.53 | #1E6B50 | 6.04 / 6.41 |
| warning | #B77924 | 3.42 ❌ / 3.64 ❌ | #8A5A10 | 5.57 / 5.91 |
| danger | #B95C63 | 4.14 ❌ / 4.40 ❌ | #A3434B | 5.71 / 6.07 |
| portal muted (hardcoded) | #7B8898 / #8895A5 / #8493A3 | 3.40 / 2.87 / 2.96 ❌ | var(--kp-muted) | 5.47 |
| portal link (hardcoded) | #0C927F | 3.64 ❌ | var(--kp-blue) | 6.19 |

Dark appearance already passed; muted/success/warning/danger were raised slightly
(#A3ADBE / #6CC6A0 / #E0B25C / #E29AA1) for margin. Typography: portal body 15px /
1.65, markdown 1.7, no text below 12px (9–10px eyebrows raised to 12px).
The console had the same issue (≈60 secondary-text selectors at 2.3–4.3:1); they now
use `--kp-muted`, and small icons were darkened to ≥ 3:1.

Re-check with `python3 scripts/verification/contrast-check.py`.
