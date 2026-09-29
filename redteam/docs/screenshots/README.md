# Screenshots

Real captures of a running instance (Playwright + headless Chromium), not
mockups — no image here was hand-edited.

| File | What it shows |
|---|---|
| `01_dashboard_overview.png` | Dashboard right after a full 11-category campaign completes |
| `02_finding_detail.png` | An expanded finding: Attack → Evidence → Impact → Remediation → Regression Test |
| `03_regression_fail.png` | Regression test on the still-vulnerable target: ❌ FAIL |
| `04_regression_pass.png` | Same regression, re-run after a real one-line fix: ✅ PASS |
| `05_dashboard_after_fix.png` | Full dashboard after the fix: score up 2.4 → 2.9, MCP Security 0.0 → 3.5, trend line ticking up |
| `dashboard-demo.gif` | All five frames combined |

Reproduce it yourself:

```bash
pip install playwright pillow
playwright install chromium

# terminal 1 & 2: run the two services (see the main README's Quickstart)

# run a campaign, then use Playwright to click through the dashboard --
# expand a finding, run its regression test, screenshot each step.
# Apply a real fix to target_agent (e.g. the get_service_token check in
# target_agent/mcp_tools.py), re-run the regression, screenshot again.
```

`dashboard-demo.gif` was assembled from the five PNGs with Pillow
(`Image.save(..., save_all=True, append_images=..., duration=[...], loop=0)`),
downscaled to 1100px wide to keep the file size reasonable.
