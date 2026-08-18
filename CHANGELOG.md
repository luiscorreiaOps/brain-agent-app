# Changelog

All notable changes to this plugin will be documented in this file, starting from its first public release.

## 1.0.0

Initial public release.

- Persistent long-term memory for Grafana AI agents, stored locally in an isolated SQLite database, partitioned by project (e.g. `sre-team`, `backend`, `default`) so context never leaks across teams.
- MCP tools exposed over RPC for reading and writing memory: `store_memory`, `upsert_memory` (skips inserting a fact that's already remembered, ignoring case/whitespace), `suggest_memory` (for an LLM's own inferred observations -- queues a pending suggestion for admin review instead of writing immediately), `search_memory`, `search_memory_by_time` (time-travel RAG over a date range), `condense_memory` (merges multiple similar/aging facts into a single "golden record"), `delete_memory`, and `brain_diagnostics` (real, measured health/telemetry -- database size, fact counts, duplicate counts, decrypt-failure counts, auto-learn poller status, process stats).
- Optional structured metadata on any stored fact: `type`, `tags`, `service`, `namespace`, `confidence`, and `expires_at` (auto-evicted once past expiry) -- all additive and optional, plain unstructured facts keep working exactly as before.
- A Brain Hub "Pending Suggestions" queue: facts an LLM suggests via `suggest_memory` (as opposed to an explicit user-requested save) sit in a pending state, invisible to search, until an admin approves or rejects them from the UI.
- Optional at-rest encryption (AES-256-GCM) for stored facts -- **opt-in, off by default**; an admin must explicitly enable it. Existing facts are unaffected either way: encryption state is recorded per-row at write time, so flipping the setting never re-encrypts or decrypts what's already on disk.
- A searchable-encryption token index (HMAC-SHA256, using a key separate from the encryption key) keeps `search_memory` fast and relevant even with at-rest encryption enabled, without ever indexing plaintext.
- Optional auto-learning from Grafana alerts: a background poller turns newly-resolved alerts into stored memories automatically, when a Grafana URL and service account token are configured -- each memory includes the alert's labels, runbook link, dashboard/panel link, and real resolution time when Grafana provides them.
- A "RPC Bus" toggle that encodes the MCP request/response payloads exchanged between the calling AI agent and this plugin -- this is transport *obfuscation* for less-readable logs/debug tools, not real encryption.
- Only Editor and Admin org roles can perform most write actions in Brain Hub (clearing memory, toggling encryption/RPC Bus, resetting the encryption key) -- enforced server-side, not just hidden in the UI. Viewers keep full read access, plus the ability to approve or reject pending LLM suggestions -- reviewing an inferred suggestion is deliberately open to everyone with access to the page.
- Per-user rate limiting on tool calls, and optional audit logging (full request/response, not just metadata) to Grafana's own backend logs.
- Configurable retention (age-based) and size-based eviction, plus exact-duplicate detection that correctly accounts for AES-GCM's random nonce (naive SQL-level dedup on the raw column would miss it).
- Health-check API so dependent AI agents know whether memory storage is available.
- Optional PII detection (opt-in, off by default): a heuristic scan runs on every new fact, flagging matches for email addresses, Brazilian CPF, US SSN, IBAN, EU VAT numbers, and Latin American national ID formats (Mexican CURP, Chilean RUT, Argentine DNI) -- never blocks the write, only surfaces a review warning in Brain Hub.
- Optional real semantic search: point `search_memory` at any OpenAI-compatible `/embeddings` endpoint in Configuration's RAG section and it ranks facts by real embedding cosine similarity instead of word-overlap scoring -- unset (the default) keeps the original word-overlap behavior exactly as-is.
- Requires Grafana >=12.0.0.
