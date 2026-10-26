# Track: DSPy

**Assess-only.** OpenProof can detect and audit a harness built on this. The free kit doesn't ship a starter or trace hook yet.

Checked against `dspy` 3.4.1 on 26 Oct 2026. `harness_track.json` lists the detect signatures. Reach is
taken from what you declare (`docs/IMPACT.md`, `.harness/REASONS.md`), because the kit has no parser for this
framework's tool lists yet. For the live red team, write each tool call to `$HARNESS_TRACE` in the format in
[TRACK_SPEC.md](../TRACK_SPEC.md), using the framework's own tool hook or a wrapper around your tools.
