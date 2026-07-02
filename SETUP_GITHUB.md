# GitHub setup — credentials & org configuration

This document lists what you (or an org admin) need to configure **Dev-Community-IO/winsaf-contracts** as a professional public repository.

## Credentials required

| Credential | Who needs it | Purpose |
|------------|--------------|---------|
| **GitHub account** with access to `Dev-Community-IO` org | You + core team | Push code, manage settings |
| **SSH key** (`git@github.com:...`) **or** HTTPS + PAT | Developers | `git push`, clone |
| **Personal Access Token (PAT)** with `repo` scope | CI, `gh` CLI, automation | API access if not using SSH |
| **`gh auth login`** (recommended) | Maintainers | Create repos, branch protection, releases |
| **Org admin role** | 1–2 people | Branch protection rules, security policies, team `@Dev-Community-IO/core` |

### What you do **NOT** need in this repo

- Telegram bot token
- JWT / database URLs
- Keeper mnemonic or deployer keys
- AWS / Cloudflare (unless you add release automation later)

Those belong in the private **`winsaf`** monorepo and server env — never in the public contracts repo.

---

## One-time: authenticate locally

```bash
# GitHub CLI (recommended)
gh auth login
# Choose: GitHub.com → SSH or HTTPS → Login via browser

# Verify
gh auth status
gh api orgs/Dev-Community-IO --jq .login

# SSH key for git (if not already)
ssh-keygen -t ed25519 -C "you@winsaf.xyz"
# Add ~/.ssh/id_ed25519.pub to GitHub → Settings → SSH keys
```

---

## Repository remotes (two repos)

| Repo | Visibility | Remote |
|------|------------|--------|
| **winsaf-contracts** | **Public** | `git@github.com:Dev-Community-IO/winsaf-contracts.git` |
| **winsaf** | **Private** | `git@github.com:Dev-Community-IO/winsaf.git` |

```bash
# Public contracts (this repo)
cd winsaf-contracts
git remote add origin git@github.com:Dev-Community-IO/winsaf-contracts.git

# Private monorepo (full product)
cd ../SAFLOTERIE   # or your winsaf folder
git init
git remote add origin git@github.com:Dev-Community-IO/winsaf.git
```

---

## GitHub UI settings (org admin)

Do these at: **https://github.com/Dev-Community-IO/winsaf-contracts/settings**

### General

- [ ] **Description:** `Open-source CosmWasm lottery contract for WinSaf on Safrochain (Apache-2.0)`
- [ ] **Website:** `https://winsaf.xyz`
- [ ] **Topics:** `cosmwasm`, `safrochain`, `lottery`, `rust`, `blockchain`, `telegram`
- [ ] Disable **Wikis** (optional — use `/docs` in repo instead)
- [ ] Enable **Issues**
- [ ] Disable **Projects** until needed

### Features → Security

- [ ] Enable **Private vulnerability reporting** (Security → Private vulnerability reporting)
- [ ] Enable **Dependabot alerts** (Settings → Code security)
- [ ] Enable **Dependabot security updates**
- [ ] Enable **Secret scanning** (org plan permitting)

### Branches → Branch protection (`main`)

- [ ] Require pull request before merging
- [ ] Require approvals: **1** (2 for mainnet releases)
- [ ] Require status checks: **CI / Rust (fmt · clippy · test · wasm)**
- [ ] Require branches to be up to date
- [ ] Do not allow bypassing (except org admins in emergencies)
- [ ] Restrict who can push: **no direct pushes** (PR only)

### Actions

- [ ] Allow GitHub Actions
- [ ] Workflow permissions: **Read repository contents** (default)

### Collaborators & teams

Create team **`@Dev-Community-IO/core`** and assign as CODEOWNERS (see `.github/CODEOWNERS`).

---

## CLI: apply settings with `gh`

Run as an org admin after the first push:

```bash
# Description + homepage
gh repo edit Dev-Community-IO/winsaf-contracts \
  --description "Open-source CosmWasm lottery contract for WinSaf on Safrochain (Apache-2.0)" \
  --homepage "https://winsaf.xyz" \
  --add-topic cosmwasm --add-topic safrochain --add-topic lottery \
  --add-topic rust --add-topic blockchain

# Enable security features (org must allow)
gh api -X PATCH repos/Dev-Community-IO/winsaf-contracts \
  -f security_and_analysis[dependabot_security_updates][status]=enabled \
  -f security_and_analysis[secret_scanning][status]=enabled

# Branch protection (adjust team/context names)
gh api -X PUT repos/Dev-Community-IO/winsaf-contracts/branches/main/protection \
  -f required_status_checks[strict]=true \
  -f required_status_checks[contexts][]='Rust (fmt · clippy · test · wasm)' \
  -f enforce_admins=true \
  -f required_pull_request_reviews[required_approving_review_count]=1 \
  -f restrictions=null
```

> Note: exact status check name appears after the first CI run on `main`.

---

## Release workflow

After merging to `main`:

```bash
git tag -a v0.1.0 -m "Initial public release"
git push origin v0.1.0
gh release create v0.1.0 \
  --title "v0.1.0" \
  --notes-file CHANGELOG.md \
  artifacts/winsaf.wasm artifacts/checksums.txt   # if built locally
```

Attach **verified wasm + checksums** to every release so auditors can compare on-chain code hashes.

---

## Syncing from the private monorepo

When contract code changes in `SAFLOTERIE/contracts/cosmwasm/`:

```bash
rsync -a --exclude target --exclude artifacts \
  ../SAFLOTERIE/contracts/cosmwasm/ ./

git add -A && git commit -m "sync: contract changes from winsaf monorepo"
git push
```

Long-term: GitHub Action in the private repo to mirror on tag — optional.

---

## Checklist summary

- [ ] `gh auth login` + org access verified
- [ ] SSH key on GitHub
- [ ] `winsaf-contracts` pushed to `main`
- [ ] Repo description, topics, homepage set
- [ ] Branch protection on `main`
- [ ] Dependabot + security alerts enabled
- [ ] Team `@Dev-Community-IO/core` created for CODEOWNERS
- [ ] First release `v0.1.0` with wasm artifact
- [ ] Private `winsaf` repo separate — secrets never committed
