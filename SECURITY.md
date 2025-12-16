# Security Policy

The kube-router maintainers take security issues seriously. We appreciate responsible disclosure and will work with you
to understand and address valid reports.

## Reporting a vulnerability

Please **do not** open a public GitHub issue, pull request, or discuss a potential vulnerability in public forums/Slack
before the maintainers have had a chance to review and respond.

Use one of the following private channels:

- Email: `admin@kube-router.io`
- GitHub (preferred when available): https://github.com/cloudnativelabs/kube-router/security/advisories/new

If you are reporting via email, include `[SECURITY]` in the subject line.

### What to include

To help us triage quickly, please include:

- A clear description of the issue and its potential impact
- Affected versions/branches (and any configuration details that matter)
- Reproduction steps or a minimal proof of concept (as appropriate)
- Any known mitigations or workarounds
- Your preferred contact information for follow-up

## Response process

When we receive a report, we aim to:

- Acknowledge receipt within **2 business days**
- Provide an initial assessment and request additional details (if needed)
- Develop and validate a fix (and backport on a best-effort basis when feasible)
- Coordinate release timing and public disclosure with the reporter

## Coordinated disclosure

We follow responsible/coordinated disclosure practices. Please give us a reasonable amount of time to investigate and
prepare a fix before publishing details. If a CVE is warranted, the maintainers will coordinate with the appropriate
CVE numbering authority.

## Supported versions

Security fixes are provided on a best-effort basis for:

- The latest released minor version
- The previously released minor version

Older versions may not receive security updates; upgrading is strongly recommended.

## Security updates

Security advisories and releases are published via GitHub. We recommend watching the repository and staying current with
upstream releases.
