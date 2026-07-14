# Contributing to aapCredsDecrypt

Thanks for helping improve aapCredsDecrypt. This guide covers local setup,
validation, and the pull request process.

## Ways to contribute

- **Report a bug** using the repository's bug report form.
- **Request a feature** using the feature request form.
- **Send a pull request** after opening an issue for non-trivial changes.
- **Report a vulnerability privately** by following [SECURITY.md](SECURITY.md).

## Prerequisites

- Python 3.12
- `ansible-core` (provides `ansible-playbook`)
- `yamllint`
- gitleaks 8.30.1 or newer

The scripts import AWX/AAP Django models and only run inside an AWX or Ansible
Automation Platform controller. You do not need a live controller to validate a
change: the checks below byte-compile the Python and syntax-check the playbooks
without importing AWX or connecting to any host.

## Set up from a clean clone

```bash
git clone https://github.com/iamteedoh/aapCredsDecrypt.git
cd aapCredsDecrypt

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ansible-core yamllint
```

Never commit `.env`, tokens, vault passwords, SSH keys, or decrypted credential
exports.

## Run the validation suite

Run the same checks that protect `main`:

```bash
python -m compileall -q .
yamllint .
ansible-playbook -i importPlaybooks/inventory.yml --syntax-check \
  importPlaybooks/aapCredsManagementPlaybook.yml \
  importPlaybooks/individualPlaybooks/import_all_credentials_ssh.yml
gitleaks git . --config .gitleaks.toml --redact --no-banner
```

When changing credential handling, exercise the affected path against a
non-production AWX/AAP controller and confirm that no plaintext secret leaks
into logs or committed files.

## Project layout

- `aapCreds.py` — current `awx-manage` management command that exports and
  decrypts credentials and imports them back from JSON
- `aapCredsManagement/` — obsolete standalone predecessor script and its README
- `importPlaybooks/` — Ansible playbook equivalents (work in progress), the
  `inventory.yml` example, and the `individualPlaybooks/` task breakdown
- `.github/workflows/` — source validation and source-only release automation

## Pull request process

1. Create a branch from `main`.
2. Make the smallest complete change and update documentation.
3. Run the full validation suite above.
4. Use a [Conventional Commit](https://www.conventionalcommits.org/) PR title:
   `feat:`, `fix:`, `docs:`, `refactor:`, `ci:`, `test:`, or `chore:`.
5. Complete the pull request template and link the related public issue.
6. Wait for all required checks to pass, then squash-merge.

The PR title becomes the squash commit subject and drives release-please:
`fix:` creates a patch release, `feat:` creates a minor release, and a `!` or
`BREAKING CHANGE:` footer creates a breaking release.

## License

By contributing, you agree that your contributions are licensed under the
project's [GNU General Public License v3](LICENSE).
