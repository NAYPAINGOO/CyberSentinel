# Milestone 2 threat model and boundaries

Assume one trusted operator hosts a local lab. Uploaded logs, source-file contents and model-generated prose are untrusted. Protect credentials, application write privileges, and the distinction between observation and interpretation.

## Implemented controls
- Salted scrypt password hashes; no default credentials; minimum 12-character CLI passwords.
- Random persistent signing key, HttpOnly/SameSite Strict cookies, one-hour inactivity lifetime, browser CSRF tokens and role checks.
- Parameterised SQL, transactional imports, input and request limits, escaped templates and self-only CSP.
- Collector uses separate random ingest-only bearer token; DB stores digest only. Token is bound to an analyst owner and can be revoked. Sixty requests/minute/token; no cookie fallback at API endpoint.
- Collector endpoint and client are intended for loopback. Client rejects remote/non-loopback URL settings and redirects; server startup binds to loopback. No remote/TLS collector deployment is supplied.
- Collector checkpoints only acknowledged batches, uses atomic replacement and OS locking, and does not execute log contents.
- AI connects only to a fixed loopback Ollama endpoint, without environment proxies or redirects. Only bounded derived facts and IDs are sent, excluding arbitrary usernames, paths, notes, IPs and raw lines.
- AI output is size/shape/reference checked and displayed as escaped unverified assistance. No tool execution, automatic remediation, status modification or alert rescoring is available to the model.

## Remaining limitations
Local administrators can modify records and token files. Audit history is not tamper-evident. Data is not encrypted at rest and raw source logs are not retained by the parser. Bearer tokens do not expire automatically: revoke when no longer needed. Signed-cookie logout cannot individually revoke a stolen cookie. No MFA, tenancy, SSO, or fine-grained incident ownership.

The server can accept a bearer-token request from a remotely reachable interface if the operator changes its binding; this is not a supported deployment. Use the supplied loopback configuration. Rate limiting is not a substitute for network access control.

File-tail rotation handling is best effort, not lossless delivery: unread old-file bytes can be missed. Content deduplication can collapse legitimate identical records. Global 10,000-event capacity and full event replay after each import are intentional local-lab limits. Alerts retain daily suppression and initial evidence snapshots.

AI outputs can hallucinate despite valid references and a restricted input. Do not present AI text as observed facts. The actual model has not been adversarially evaluated. A local model may be slow; one synchronous generation can occupy a worker for up to 90 seconds. Generation concurrency is limited per process, not globally across separate servers.

Keep instance data, token files, real logs and secrets out of Git. Token file mode is owner-only on POSIX; on Windows protect the folder through appropriate ACLs. No formal penetration test or vulnerability scan was conducted. Public deployment requires a separate security and architecture review.
