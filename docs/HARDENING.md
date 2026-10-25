# Hardening checklist (the owner's switches)

The ledger's hash chain shows when an entry was edited, but someone with write access could rebuild the whole file.
These GitHub settings are what make that, and unreviewed approvals, impossible to slip in. Do them once per repo.

## 1. CODEOWNERS
Copy `plugins/harness-init/skills/init/templates/CODEOWNERS` to `.github/CODEOWNERS` in your project, replace
`@your-github-user` with your handle, commit.

## 2. Branch protection on `main` (Settings → Branches → Add rule, or Rules → Rulesets)
- Require a pull request before merging, with **Require review from Code Owners**
- **Require status checks to pass**: select `harness / proof` (and `validate` in this repo)
- **Require signed commits**
- Do not allow force pushes or deletions; apply the rule to administrators too

Same thing from a terminal (adjust the repo and check names):
```bash
gh api -X PUT repos/<owner>/<repo>/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["proof"]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"require_code_owner_reviews": true, "required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
gh api -X POST repos/<owner>/<repo>/branches/main/protection/required_signatures
```

## 3. Signed commits
`git config --global gpg.format ssh && git config --global user.signingkey ~/.ssh/id_ed25519.pub && git config --global commit.gpgsign true`,
then add the same public key on GitHub as a **Signing key** (Settings → SSH and GPG keys).

## 4. CI proof
Copy `plugins/harness-init/skills/init/templates/.github/workflows/harness.yml` to `.github/workflows/`. It runs
`harness check` and `harness reverify` on a clean runner and, on public repos, signs the evidence records.

## 5. Approvals
Only you run `harness approve` and `harness signoff`. With rules 1–3 on, an approval reaches `main` only through a
reviewed, signed commit.
