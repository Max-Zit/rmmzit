# Security policy

## Supported versions

Security fixes are released for the newest RMMZit version. The server checks for updates and installs signed releases from *Settings → Version and updates*; agents update themselves to the server's version.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/rmmzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## Security design

- The console and the agent endpoint listen on separate ports; the console accepts connections only from allowed networks, checked before TLS.
- Agents connect outbound only and pin the server certificate. Every command to an agent is signed by the server and checked by the agent.
- Two-factor sign-in (TOTP) for local and LDAP accounts, argon2id passwords, short sessions, progressive blocking of failed sign-ins, CSRF protection and a strict Content Security Policy.
- Roles (administrator, technician, read-only) and per-customer access; a hash-chained audit log.
- Root actions of the console (updates, network, time zone) go through a separate root helper with a fixed set of validated requests.
- Diagnostics remove passwords, tokens, enrollment codes and keys from everything they show or export.

## How releases are protected

- Every release has a manifest signed with the RMMZit release key (ed25519); the server, the agents and `install.sh` verify the signature and checksums before installing.
- Release packages are built from tagged commits of this repository; the appliance images carry a written source offer (`SOURCE-CODE.txt`).

## How RMMZit is tested

**On every change** (GitHub Actions):

- build for Linux and Windows, gofmt, `go vet`, the full test suite (against an embedded PostgreSQL), and the whole suite again with the Go **race detector**;
- **fuzzing** of every parser that reads untrusted input — agent messages, signed commands, remote desktop tiles, registry paths, enrollment codes, winget and Chocolatey output, backup files (restore, import, decryption), SFTP answers, release manifests, network allow-lists, sign-in redirects, SSO state, SAML metadata and responses, uploaded certificates and lists typed into forms;
- staticcheck and gosec (Linux and Windows), govulncheck (a known vulnerability in called code fails the build unless it is listed with a reason and an end date in `.govulncheck-accepted`), Gitleaks, CodeQL, Dependabot, secret scanning with push protection and the [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Max-Zit/rmmzit).

**Before every release**, in a test lab:

- source code: Semgrep, Trivy and Gitleaks;
- the running console: an authenticated OWASP ZAP scan of a freshly installed appliance, a crawl of every page as administrator, technician and read-only user (forms, buttons, links), and probes that every write or admin route refuses the roles that may not use it;
- the appliance image: Trivy over its operating-system packages, a Lynis hardening audit, testssl.sh on the console (8443) and agent (8444) ports, and Nuclei; the container image `ghcr.io/max-zit/rmmzit`: Trivy; OpenVAS / Greenbone for larger releases;
- an end-to-end regression on real Windows and Linux machines (enrollment, monitoring, alerts, remote desktop, terminal, files, scripts, updates, roles, LDAP and SSO), and the appliance images imported on Proxmox, VMware ESXi and Hyper-V.

Findings are fixed before the release; accepted risks are documented in the release notes.
