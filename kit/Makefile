# Harness Starter Kit. Put this folder inside your repo as ./harness, then run from it:
#   make help
TRACK ?= claude-code
REPO  ?= $(abspath ..)
VENV  := .venv/$(TRACK)
PY    := $(VENV)/bin/python
PF    := npx --yes promptfoo@0.125.1
PRE   := $(if $(filter microsoft-agent-framework,$(TRACK)),--pre,)   # only MAF needs pre-release connectors
TRACKS := claude-code claude-agent-sdk microsoft-agent-framework google-adk langgraph openai-agents-sdk crewai strands-agents
ASSESS_ONLY := $(shell cd tracks && grep -l '"assess-only"' */harness_track.json 2>/dev/null | cut -d/ -f1)

.PHONY: help install devcontainer setup setup-redteam check proof audit redteam-live redteam-selftest run smoke eval redteam-promptfoo redteam-deepteam

help:
	@echo "TRACK = one of: $(TRACKS)   (now: $(TRACK))"
	@echo "Assess-only (no starter yet, see tracks/TRACK_SPEC.md): $(ASSESS_ONLY)"
	@echo "REPO  = your project root     (now: $(REPO))"
	@echo ""
	@echo "make install TRACK=..        copy work list, init.sh, check script (+ Claude Code files) into REPO; never overwrites"
	@echo "make devcontainer            copy the dev container config into REPO (VS Code / Codespaces)"
	@echo "make setup TRACK=..          create .venv/<track> and install that track's packages"
	@echo "make setup-redteam TRACK=..  add DeepTeam to the track's venv"
	@echo "make audit                   score REPO's harness across 7 areas (evidence + fixes)"
	@echo "make check                   validate REPO/progress/feature_list.json"
	@echo "make proof                   harness check: criteria approved, every pass backed by hash-bound evidence"
	@echo "make redteam-live             live red team on the real tool path (needs live.json + baseline)"
	@echo "make redteam-selftest         prove the live detectors fire and stay quiet (no model needed)"
	@echo "make run TRACK=..            run the track's harness on the next failing item in REPO"
	@echo "make smoke                   offline wiring check through promptfoo (no API key)"
	@echo "make eval TRACK=..           promptfoo behaviour evals against the track"
	@echo "make redteam-promptfoo TRACK=..   promptfoo red team"
	@echo "make redteam-deepteam TRACK=..    DeepTeam red team (FRAMEWORK=agentic|owasp-asi-2026|owasp-llm)"

install:
	@test -d "$(REPO)" || (echo "REPO not found: $(REPO)"; exit 1)
	@mkdir -p "$(REPO)/progress" "$(REPO)/scripts"
	@cp -n shared/progress/feature_list.json shared/progress/progress.md shared/progress/clean-state.md "$(REPO)/progress/" 2>/dev/null || true
	@cp -n shared/progress/DECISIONS.md "$(REPO)/DECISIONS.md" 2>/dev/null || true
	@cp -n shared/scripts/check_feature_list.py shared/scripts/harness.py "$(REPO)/scripts/" 2>/dev/null || true
	@(cd "$(REPO)" && git rev-parse --git-dir >/dev/null 2>&1 && python3 scripts/harness.py init >/dev/null) || true
	@(cp -n shared/init.sh "$(REPO)/init.sh" 2>/dev/null; chmod +x "$(REPO)/init.sh") || true
	@if [ "$(TRACK)" = "claude-code" ] || [ "$(TRACK)" = "claude-agent-sdk" ]; then \
	  cp -n tracks/claude-code/CLAUDE.md "$(REPO)/CLAUDE.md" 2>/dev/null || true; \
	  mkdir -p "$(REPO)/.claude" && cp -rn tracks/claude-code/.claude/. "$(REPO)/.claude/" 2>/dev/null || true; \
	  chmod +x "$(REPO)/.claude/hooks/"*.sh; \
	fi
	@echo "Installed into $(REPO). Existing files were left untouched. Next: fill in CLAUDE.md, init.sh, progress/feature_list.json"

devcontainer:
	mkdir -p "$(REPO)/.devcontainer"
	cp -n environments/devcontainer/.devcontainer/* "$(REPO)/.devcontainer/" 2>/dev/null || true
	@echo "Open $(REPO) in VS Code and choose 'Reopen in Container', or create a Codespace."

setup:
	@if [ "$(TRACK)" = "claude-code" ]; then \
	  command -v claude >/dev/null || npm install -g @anthropic-ai/claude-code; \
	  command -v jq >/dev/null || echo "Install jq for the test-output hook (brew install jq / apt install jq)"; \
	  claude --version; \
	elif [ ! -f tracks/$(TRACK)/requirements.txt ]; then \
	  echo "No starter for TRACK=$(TRACK) (assess-only or unknown). See tracks/TRACK_SPEC.md"; exit 1; \
	else \
	  python3 -m venv "$(VENV)" && $(PY) -m pip install -q --upgrade pip && \
	  $(PY) -m pip install -q $(PRE) -r tracks/$(TRACK)/requirements.txt && echo "Ready: $(VENV)"; \
	fi

setup-redteam:
	@test "$(TRACK)" != "claude-code" || (echo "Pick a code track (any of $(TRACKS) except claude-code)"; exit 1)
	$(PY) -m pip install -q -r testing/deepteam/requirements.txt

audit:
	python3 $(abspath ../plugins/harness-audit/skills/audit/scripts/audit.py) "$(REPO)"

check:
	cd "$(REPO)" && python3 scripts/check_feature_list.py

run:
	@case "$(TRACK)" in \
	  claude-code) echo "cd $(REPO) && claude   then: 'Run the resume skill, then work on the next item.'";; \
	  claude-agent-sdk) $(PY) tracks/claude-agent-sdk/agent.py --repo "$(REPO)";; \
	  microsoft-agent-framework) KIT_REPO="$(REPO)" $(PY) tracks/microsoft-agent-framework/harness_agent.py --repo "$(REPO)";; \
	  google-adk) KIT_REPO="$(REPO)" $(VENV)/bin/adk web tracks/google-adk;; \
	  langgraph|openai-agents-sdk|crewai|strands-agents) KIT_REPO="$(REPO)" $(PY) tracks/$(TRACK)/agent.py --repo "$(REPO)";; \
	  *) echo "No starter for TRACK=$(TRACK) (assess-only or unknown). See tracks/TRACK_SPEC.md"; exit 1;; \
	esac

smoke:
	@cd testing/promptfoo && KIT_TRACK=echo PROMPTFOO_PYTHON=python3 $(PF) eval -c smoke.yaml --no-cache

eval:
	cd testing/promptfoo && KIT_TRACK=$(TRACK) KIT_REPO="$(REPO)" PROMPTFOO_PYTHON=$(abspath $(PY)) $(PF) eval

redteam-promptfoo:
	cd testing/promptfoo && KIT_TRACK=$(TRACK) KIT_REPO="$(REPO)" PROMPTFOO_PYTHON=$(abspath $(PY)) $(PF) redteam run -c redteam.yaml

FRAMEWORK ?= agentic
redteam-deepteam:
	KIT_TRACK=$(TRACK) KIT_REPO="$(REPO)" $(PY) testing/deepteam/red_team.py --framework $(FRAMEWORK)

proof:
	cd "$(REPO)" && python3 scripts/harness.py check

redteam-selftest:
	python3 testing/live/redteam_live.py --repo "$(REPO)" selftest

redteam-live:
	python3 testing/live/redteam_live.py --repo "$(REPO)" run --attacks "$(ATTACKS)"
