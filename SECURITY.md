# Security Policy

## Reporting a vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide the details requested below.

If private reporting is unavailable, contact the maintainer through the
[iamteedoh GitHub profile](https://github.com/iamteedoh).

## What to include

- A description of the issue and its potential impact
- Reproduction steps or a minimal proof of concept
- The affected release, commit, script, or playbook
- A suggested remediation, if known

Never include live bearer tokens, passwords, SSH keys, vault passwords,
decrypted credential exports, private hostnames, or unredacted logs in a report.

## Security-sensitive areas

aapCredsDecrypt decrypts and exports AWX/AAP credential secrets, so the most
sensitive surfaces are:

- Decryption of secret fields and the resulting plaintext credential JSON
- Storage, transfer, and cleanup of exported credential files
- Ansible Vault password files and vault encrypt/decrypt handling in the
  import playbooks
- `awx-manage shell_plus` command construction that interpolates credential,
  organization, and role names (injection risk)
- Re-establishment of user, team, and job template access on import

## Handling exported credentials

Exports contain decrypted secrets in cleartext. Treat every export file as a
live secret: keep it off shared storage, encrypt it at rest, and delete it as
soon as the migration is complete.

## Supported versions

Security fixes land on `main` and ship in the next tagged source release. Test
against the latest release or `main` before reporting an issue.
