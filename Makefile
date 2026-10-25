# Checks for the marketplace repo itself.
.PHONY: check test audit validate
check: test audit validate
test:
	python3 -m unittest discover -s tests -v
audit:
	python3 plugins/harness-audit/skills/audit/scripts/audit.py . --min 80
validate:
	claude plugin validate . && for p in plugins/*; do claude plugin validate "$$p"; done
	python3 scripts/check_feature_list.py
