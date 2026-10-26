# Decisions

One line per decision. Later sessions read this instead of reopening settled questions.

| Date | Decision | Who decided | Why |
|---|---|---|---|
| 2026-10-25 | Ship as a Claude Code plugin marketplace plus a multi-framework kit | Yen-Ching Wu | One-command install for Claude Code users, same discipline for other frameworks |
| 2026-10-25 | Build on Learn Harness Engineering's ideas with credit, no copied files | Yen-Ching Wu | Recycle the best approach; add safety, evals and cost areas the course leaves out |
| 2026-10-26 | Extend the kit with four tracks supported (full) — LangGraph, OpenAI Agents SDK, CrewAI, AWS Strands Agents — and assess-only tracks for the next most used frameworks | Yen-Ching Wu | Cover the frameworks buyers' teams already use without diluting "proof, not words": full only where the kit ships a real trace hook and smoke test |
| 2026-10-26 | Add Vercel AI SDK as an eighth assess-only track; no separate tracks for AutoGen or Semantic Kernel (Microsoft Agent Framework succeeds them) | Cowork, for owner review | Vercel AI SDK is current and widely used in TypeScript; separate AutoGen/SK tracks would duplicate MAF |
| 2026-10-26 | Every track describes itself in harness_track.json (harness-track/1) | Cowork, for owner review | One shape that the kit, its tests and assessors such as OpenProof can read without per-framework code |
| 2026-10-26 | Guard checks G1-G3 judge each framework by its own mechanism (explicit tool list, approval or deny gate); declared evidence for assess-only tracks earns half weight; a check passes only when every agent surface passes | Yen-Ching Wu (approved the fix) | A narrow non-Claude harness lost up to 8 of 100 points for not using .claude/settings.json; the same guard quality must earn the same points |
