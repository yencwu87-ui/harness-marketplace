# Codex round-1 fixtures (review data)

Copied from Codex's evidence package for kit 1.4.1 (`kit_harness_marketplace_24bc1da4_src`, round 1, 26 Oct 2026):
the fairness matrix fixtures (`<track>/a|b|c`), the extra probes, the assess-only fixtures and the
generated-code harness scenario. `probes/` holds Codex's probe scripts for reference; tests do not run them.
All repositories, names and inputs are constructed. The audit reads these files; nothing here is imported or run
by the audit.

- a: narrow tools, broad capabilities unavailable or denied. Expected 8/8 guard points.
- b: broad shell and web, no functioning guard. Expected 0/8.
- c: shell guarded (inline refusal + the framework's own gate), web fetch ungated. Expected 2/8 (G3 kept,
  G1 and G2 lost for the ungated fetch).
