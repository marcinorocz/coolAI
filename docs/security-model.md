# Security model and integration contract

## Trust boundaries

The agent and its proposed arguments are untrusted. The operator owns the policy,
bindings, upstream executable, signing key and state directory. The upstream
implementation must faithfully implement the semantics assigned to its tools.

A trusted binding supplies the operation, classification, input schema and
destination extraction. No classification is inferred from the agent's prose or
MCP read-only hints. Binding an arbitrary tool to `read` does not make it read-only.
Classify each tool conservatively: use all data classes it may handle.
For document-specific classification, build a trusted adapter that queries
authoritative metadata, then invokes the executor with that classification.

The integration path is:

1. Match the upstream tool name to a trusted binding.
2. Validate and snapshot the complete arguments.
3. Derive the operation, destination and data classes.
4. Evaluate policy and persist a minimal decision record.
5. If required, verify and atomically consume a matching operator approval.
6. Persist dispatch intent, then invoke the upstream with the same snapshot.
7. Record completion or error without storing output.

Use the executor as the only route to tool credentials and effects. A host
application that bypasses it bypasses its protection. This is not an OS sandbox.

## Decisions and destinations

Unknown tool/operation pairs and unsupported or missing targets are blocked.
All registered writes, sends, deletion, publication, signing and transfers need
approval even if `approval_operations` is empty. That field may add requirements,
not remove these baseline protections. Sensitive reads and external reads also
need approval. Only registered internal, nonsensitive reads are allowed directly.

Sensitive external transfer additionally requires an exact trusted domain and
explicit authorization of each data class. Secrets and credentials cannot be
authorized for external transfer. Domains do not implicitly cover subdomains.
Mail recipients must be single plain addresses, not display names or lists.

Targets reject userinfo, query strings, percent encodings, fragments, whitespace,
unknown schemes and nonstandard ports. These conservative restrictions are
intentional for 0.2. Supply a trusted adapter for richer addressing.

A destination check is not SSRF protection, DNS pinning, redirect enforcement or
egress isolation. The actual network adapter must control those separately.
An internal URI is a trusted adapter convention, not proof that content is safe.

## Approvals

Approvals use HMAC-SHA256, expire after 1–3600 seconds, and are single-use across
process restarts and concurrent consumers sharing the same SQLite database.
They bind the upstream tool name, full argument snapshot, policy, bindings and
upstream command/arguments/working directory. A policy or binding change
invalidates prior approvals. A `block` is never overridden.

The operator CLI is a trusted administrative capability. `--actor` records a
label, not a verified login. Possession of the key authorizes signing; there is
no separate authentication service or user directory in this release.
Keep the key and database inaccessible to the agent and upstream process.
Use an operator-owned directory with mode 0700 and regular state files with mode
0600. Existing group/world-accessible state files are rejected on POSIX.
Do not expose `approve` or unrestricted shell access to the agent.

HMAC verification and issuance share a secret. Separate signing and verification
trust domains will require asymmetric signatures in a later release.
SQLite must be on a local filesystem with reliable locking. Multiple hosts need
a shared transactional service, which is not implemented.

A consumed approval is not restored after a timeout, crash or upstream failure.
This gives at-most-one dispatch attempt per approval, not exactly-once side
effects. Inspect upstream state before retrying and obtain a fresh approval.
For tools referring to mutable documents, include a version/hash in the
arguments and enforce it in the upstream adapter; argument binding cannot
freeze an external document.

## Audit and errors

Audit events include timestamp, request ID, decision, stable rule IDs, fingerprints,
phase and an operator label after approval. Prompts, raw targets, input/output
payloads and tokens are excluded. Fingerprints are identifiers, not encryption;
protect logs against guessing attacks on low-entropy inputs and treat operator
labels as identifying data.

Audit failure before dispatch prevents execution. Failure after dispatch cannot
undo effects. A crash can leave a dispatching event without a completion event.
Upstream MCP tool errors are returned as MCP errors; completion means the call
returned, not that a business transaction succeeded.
SQLite audit storage is durable but **not tamper-evident**. An administrator can
modify it. No claim of a cryptographic audit chain is made.

## Prompt injection and data loss

The regular-expression checks recognize a few English and Polish patterns.
They can miss attacks and reject innocent quotations. They are a supplementary
signal, not a general prompt-injection defense. Capability restrictions, trusted
bindings and explicit approvals remain the enforcement mechanism.

This release does not discover personal data, scan attachments, redact tool
responses, or track data flowing through a sequence of agent calls. It cannot
detect a secret routed through a tool incorrectly classified as public.
Real deployments must supply authoritative classifications and isolate secrets.

## Scope

Supported: deterministic local policies, bounded JSON/YAML configuration, one
stdio MCP upstream, tools-only forwarding, local operator approvals.
Not implemented: remote transport authentication, multi-tenant identities,
distributed replay prevention, model/content safety certification, telemetry,
automatic regulatory compliance or a universal agent firewall.
