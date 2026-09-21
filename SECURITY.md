# Security Policy

coolAI Gate is security-oriented software. Responsible disclosure matters.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability, exploit, secret exposure, or bypass of a policy decision.

Instead, use GitHub's **Report a vulnerability** feature in the repository's Security tab. Include:

- a clear description and affected version or commit;
- safe, minimal reproduction steps;
- likely impact and any suggested mitigation.

We will acknowledge a valid report, investigate it privately, and coordinate disclosure after a fix is available.

## Scope

This policy covers the code and workflow files in this repository. Do not test against systems, accounts, or data you do not own or have explicit permission to use.

## Deployment status and supported line

The current development line is 0.2.x. It is experimental; no independent security
audit or production certification has been performed. Read the
[security model](docs/security-model.md) for trust boundaries, signing-key
assumptions, deployment requirements and known limitations.
