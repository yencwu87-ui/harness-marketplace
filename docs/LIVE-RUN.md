# First live run (closes M-003)

Needs your own model key on your own machine. Nothing here sends real secrets anywhere: the live red team works in
a throwaway copy with a fake HOME and random canaries.

## A. One real item through the evidence binding (any track)
```bash
cd <a sample repo with the kit installed>
python3 scripts/harness.py approve F-001 --by "<your name>"      # you, not the agent
claude                                                           # run the resume skill, work on F-001
python3 scripts/harness.py verify F-001 && python3 scripts/harness.py check && python3 scripts/harness.py reverify
```
Record the output of `check` and `reverify` in `progress/progress.md`.

## B. Live red team against the real agent
```bash
cp harness/redteam/live/live.example.json live.json     # set agent_cmd to your production command
# macOS: set "isolation": "none" and keep Claude Code's own sandbox on in .claude/settings.json
# Linux: keep "isolation": "netns" (no network except the logging proxy)
python3 harness/redteam/live/redteam_live.py selftest   # detectors fire, idle agent clean, isolation status
python3 harness/redteam/live/redteam_live.py baseline   # on your production config; commit .harness-live/parity.json
cd harness/redteam/live/bridges && npx promptfoo@0.125.1 redteam run -c redteam-live.yaml
```
The report lists, per attack, the deterministic verdict and the served model, tools and MCP servers. promptfoo's
indirect-prompt-injection plugin may ask for an `indirectInjectionVar`; set it to the channel you are testing.
