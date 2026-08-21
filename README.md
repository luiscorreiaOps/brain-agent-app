<table>
<tr>
<td width="110" valign="middle" align="center"><img src="https://raw.githubusercontent.com/luiscorreiaOps/brain-agent-app/main/src/img/brain-logo.png" width="90" alt="Brain Agent" style="border-radius: 10px;" /></td>
<td valign="middle">

# Brain Agent
*Brain Agent is the memory engine for Agent AI. It provides long-term memory, Retrieval-Augmented Generation (RAG), and project-aware context management for AI assistants running inside Grafana.*

</td>
</tr>
</table>

---

Brain Agent is a Grafana app plugin that serves as a standalone memory and
RAG service for your Grafana AI ecosystem. It allows other plugins (like
Agent AI) to store, search, and manage context across different user
sessions.

With Brain Agent, AI assistants retain knowledge across sessions --
infrastructure details, project guidelines, runbooks, and debugging steps
from past interactions.

## Works with Agent AI

Brain Agent can operate independently (its HTTP API and MCP tools work on
their own), but it's primarily designed to work alongside **[Agent AI](https://github.com/luiscorreiaops/agent-ai-app)**.
Install both and enable **Brain Agent Tools** in Agent AI's
Configuration to turn on:

- Long-term memory (`store_memory`/`upsert_memory`/`search_memory`)
- Automatic memory pre-fetch for the dashboard/panel being viewed
- RAG retrieval by relevance, with usage-based decay (see below)
- Root-cause investigation backed by past incidents
- Curated runbook retrieval (`retrieve_runbook` -- only reviewed, approved
  `type="runbook"` facts, never any other remembered fact)
- Project-aware conversations

Agent AI talks to Brain Agent through one shared service account, deliberately
kept at Viewer (see Agent AI's own docs on why). Under that setup,
`store_memory`/`upsert_memory`/`delete_memory`/`condense_memory` always
return 403 through this integration -- that's permanent, not a bug. The four
read tools (`search_memory`/`search_memory_by_time`/`brain_diagnostics`/
`retrieve_runbook`) can be opened up for that one shared account
specifically: set **Trusted Integration Login** in Brain Agent's
Configuration to that service account's exact login (Grafana's format is
`sa-<orgId>-<name>`, not just the name you gave it) to let it read memory
without granting write access or opening reads to any other Viewer. Leave
the field empty to keep the original, narrower default: only
`suggest_memory` works end to end through this integration.

## Screenshots

![Brain Hub](https://raw.githubusercontent.com/luiscorreiaOps/brain-agent-app/main/src/img/screenshots/brain-hub.png)
![Structured memory & pending suggestions](https://raw.githubusercontent.com/luiscorreiaOps/brain-agent-app/main/src/img/screenshots/structured-memory-and-suggestions.png)
![Configuration](https://raw.githubusercontent.com/luiscorreiaOps/brain-agent-app/main/src/img/screenshots/configuration-page.png)

## What it does

| Feature | Description |
|---|---|
| Persistent Memory | Store key facts and infrastructure details automatically in an isolated SQLite database. |
| RAG Capabilities | Relevance-scored search to retrieve relevant context when an AI agent needs background information. |
| Real Semantic Search (optional) | Point `search_memory` at any OpenAI-compatible `/embeddings` endpoint (Ollama, OpenAI, or a compatible gateway) in Configuration's RAG section and it ranks facts by real embedding cosine similarity -- e.g. "Vault became unavailable after a pod restart" is found by "secrets manager outage" with zero words in common. Unset (the default) keeps the original word-overlap scoring exactly as-is; a fact written before this was configured just falls back to word-overlap search until it's re-saved. |
| Usage-Based Decay | Every ranking path (embeddings, indexed lexical, full-scan lexical) weights its score by a half-life decay (14 days, floored so decay only ever re-orders matches, never hides the strongest one) since a fact was last matched by a search, or created if never matched again. A stale fact nobody has needed in months (an old IP/DNS entry that still text-matches perfectly) naturally loses ranking priority against one that keeps getting confirmed relevant. |
| Structured Metadata | Optional `type`/`tags`/`service`/`namespace`/`confidence`/`expires_at`/`author` (who curated/confirmed the fact -- most useful for `type="runbook"` facts) on any fact, for filtering, automatic expiry, and attribution -- plain unstructured facts keep working exactly as before. |
| Curated Runbook Retrieval | `retrieve_runbook` returns only `type="runbook"` facts that are also `status="approved"` -- reuses the existing suggestion/approval workflow rather than a separate review concept, so a reader only ever gets reviewed, trusted procedures, never any old chat observation that happened to get remembered under a different type. |
| Approval Queue | Facts an LLM infers on its own (as opposed to an explicit user-requested save) land as pending suggestions for an admin to review from the Brain Hub UI before they become real, searchable memories. Approving one requires Editor or Admin (it promotes an unreviewed suggestion into real memory); rejecting one -- discarding it, strictly lower-risk -- stays open to any Viewer. |
| Isolated Tenancy | Two levels: if multiple Brain Agents are installed (e.g. forks), each gets its own independent database file automatically -- *and*, on a single install shared by multiple Grafana organizations, each organization gets its own database file too, so orgs never share rows even on the same Grafana. |
| Project Grouping | Memory is partitioned by project (e.g., `sre-team`, `backend`, `default`), preventing context leakage. |
| Health Monitoring | Exposes a reliable healthcheck API so dependent AI agents know if memory storage is available. |
| PII Detection (opt-in) | When enabled in Configuration's Compliance & Auditing section, every new fact is scanned by a heuristic (email, CPF, US SSN, IBAN, EU VAT, card-shaped digit runs, long tokens, plus Latin American formats -- Mexican CURP, Chilean RUT, a generic DNI/cédula pattern) and flagged in Brain Hub for human review if it matches -- never blocks the write, and isn't a compliance guarantee, just a signal. |
| Auto-Learning from Alerts (opt-in) | A background poller watches Grafana's alerting API and turns newly-resolved alerts into stored memories on its own -- see [Auto-Learning From Alerts](#auto-learning-from-alerts) below. |

## Technical Details

### Internal Storage
- **Database:** Brain Agent stores all approved facts in a local SQLite database, specifically located at `/var/lib/grafana/brain-agent.db` by default.
- **SQL Injection Protection:** The plugin's code uses strictly **prepared statements** (`?` bind parameters) for every SQLite interaction. Text coming from the AI is treated strictly as *data*, so it can never inject SQL commands that corrupt the database or alter another project's records.

### Encryption at Rest
- **At-rest encryption (opt-in, off by default):** an admin can enable AES-256-GCM encryption for every new memory fact. The key is generated and stored locally the first time it's enabled. Existing facts keep whatever state they were written with -- flipping the setting never re-encrypts or decrypts what's already on disk.

### Searchable Encryption
- **Searchable encryption index:** because AES-GCM uses a random nonce per encryption, two encryptions of the same plaintext produce different ciphertext -- so a plaintext-indexed search would stop working once at-rest encryption is on. To keep `search_memory` fast and relevant either way, facts are also indexed by an HMAC-SHA256 token index, using a key kept separate from the encryption key, so the index never stores plaintext.

### Transport Protection
- **RPC Bus (optional):** base64-encodes the MCP request/response body between this plugin and the calling AI agent. This is transport *obfuscation* for less-readable logs/debug tools -- it is **not** encryption.

### Audit Logging
- **Rate limiting & audit logging:** per-user rate limiting on tool calls, and optional audit logging (metadata by default, full request/response content opt-in) to Grafana's own backend logs.

### PII Detection
- **PII detection (opt-in, off by default):** when enabled from Configuration's Compliance & Auditing section, a regex-based heuristic scan runs on every new fact (`store_memory`/`upsert_memory`/`suggest_memory` all go through it), flagging matches for email addresses, Brazilian CPF, US SSN, IBAN, EU VAT numbers, card-shaped digit runs, long API-key-shaped tokens, and Latin American national ID formats (Mexican CURP, Chilean RUT, a generic DNI/cédula pattern). A flagged fact still gets stored/suggested normally -- the flag only surfaces a review warning in Brain Hub.

### How a request flows through the system

```
Any AI assistant plugin (e.g. Agent AI)
        │
        ▼
  MCP (tools/list, tools/call)
        │
        ▼
    Brain Agent  ◄──── Grafana Alerts API (Auto-Learning poller, opt-in)
        │
        ▼
     SQLite
```

### MCP Protocol (Model Context Protocol)
Most read/write interaction with memory happens over the MCP standard on RPC, via two JSON-RPC methods: `tools/list` (returns the available memory tools) and `tools/call` (executes one of them). The available tools are:

- `store_memory` -- takes `{"fact": "...", "project": "..."}` to store a fact in long-term memory. Also accepts optional structured metadata: `type`, `tags` (comma-separated), `service`, `namespace`, `confidence` (0.0-1.0), `expires_at` (ISO8601 -- the fact is auto-evicted once past this time), and `author` (who curated/confirmed it).
- `upsert_memory` -- same as `store_memory` (including the same optional metadata fields), but skips inserting if a canonically identical fact (same words, ignoring case/whitespace) is already stored for that project -- prefer this when you might be re-observing something already known.
- `suggest_memory` -- takes `{"fact": "...", "project": "..."}` like `store_memory`, but for an LLM's own *inferred* observations rather than something a user explicitly asked to save. It does not write immediately -- the fact lands as a pending suggestion for review from the Brain Hub UI before it becomes a real, searchable memory: approving it requires Editor or Admin, rejecting it is open to any Viewer. Explicit "remember X"/"save this" requests should still use `store_memory`/`upsert_memory` directly.
- `search_memory` -- searches memory by relevance, taking `{"query": "...", "project": "..."}`. Only ever returns approved, non-expired facts. Ranking includes usage-based decay -- see the table above.
- `search_memory_by_time` -- time-travel RAG over a date range, taking `{"query": "...", "start_time": "...", "end_time": "..."}`.
- `retrieve_runbook` -- takes `{"query": "...", "project": "..."}` (both optional) and returns only `type="runbook"` facts that are also `status="approved"`. Use this instead of `search_memory` when you specifically want a curated runbook/procedure, not any memory fact.
- `condense_memory` -- merges and distills multiple similar/aging memories into a single "golden record" runbook to save space (`{"condensed_fact": "...", "facts_to_delete": [...]}`).
- `delete_memory` -- removes a specific fact, given in `{"fact": "..."}`.
- `brain_diagnostics` -- returns real, measured health/telemetry: database size, fact/duplicate counts, decrypt-failure counts, auto-learn-from-alerts poller status, and process stats (not hardcoded placeholders).

### HTTP Management Endpoints
These endpoints are intended for administration and the Brain Hub UI. AI
agents should normally interact with Brain Agent through the MCP tools
above, not by calling this HTTP API directly. For state-management and UI
actions, Brain Agent exposes the following HTTP routes:

- `GET /health` : returns `{"status": "ok"}` when the database is reachable.
- `GET /facts?project=...` : lists approved, non-expired stored facts (with their structured metadata) for a project, for the Brain Hub UI.
- `GET /pending_facts?project=...` : lists LLM-suggested memories (via `suggest_memory`) still awaiting admin approval.
- `POST /pending_facts/approve?id=...` : promotes a pending suggestion to a real, searchable memory. Requires Editor or Admin -- it's the review's outcome, not the review itself.
- `POST /pending_facts/reject?id=...` : discards a pending suggestion permanently. Open to any Viewer -- discarding an unreviewed suggestion is strictly lower-risk than promoting one.
- `GET /stats` : usage metrics and memory counts grouped by project (approved facts only).
- `DELETE /memory?project_id=...` : clears memory. Send `project_id=all` to clear globally, or a specific project id (e.g. `default`) to clear just that scope.
- `POST /crypto/reset` : disaster recovery, Admin-only. Backs up the current database and encryption keys atomically (fsynced, all-or-nothing) with a timestamp suffix, then generates fresh keys and an empty database -- this **replaces the database**, it does not just rotate the key over existing data. Only reach for this on real corruption or key loss; recovering the old backup files afterward requires manual, deliberate action.
- `GET /encryption_in_transit/status` : whether the RPC Bus (base64) obfuscation is enabled.
- `POST /encryption_in_transit/toggle` : turns the RPC Bus obfuscation on/off.

### Auto-Learning From Alerts
When enabled with a Grafana URL and service account token, a background poller watches Grafana's alerting API and turns newly-resolved alerts into stored memories automatically -- the only automatic (non-explicit-tool-call) path into memory that exists in this plugin. Each memory includes the alert's labels (namespace/service/severity), a runbook link and a dashboard/panel link when Grafana provides them, and the alert's real resolution time.

## Installation

1. Install Brain Agent (unzip a release into your Grafana instance's plugins directory, or via the Grafana plugin catalog once published).
2. Enable the plugin.
3. (Optional) Configure at-rest encryption, PII detection, or Auto-Learning from Alerts in Configuration.
4. Install **[Agent AI](https://github.com/luiscorreiaops/agent-ai-app)** (or another compatible assistant plugin).
5. Enable **Brain Agent Tools** in that plugin's Configuration.
6. Create your first project (any `project` value passed to a memory tool call).
7. Start using long-term memory -- ask the assistant to remember something, or let it suggest its own observations for review.

Once installed and enabled, Brain Agent runs in the background and makes its APIs available to other plugins.

## Releases & Supply Chain

Every tagged release (`.github/workflows/release.yaml`):

- Builds the plugin (frontend + Go backend), and signs it if
  `GRAFANA_ROOT_URLS` is configured (private signature, tied to that root
  URL) -- see the callout in `deploy/deployment.yaml` if you're running an
  unsigned build.
- Builds and pushes a Docker image with the plugin baked in, with
  BuildKit-native SBOM and provenance attestations attached to the pushed
  image (`docker buildx imagetools inspect` against the image digest to
  read either).
- Actions and third-party tool downloads (e.g. gitleaks) are pinned by
  commit SHA, not a mutable tag or version range.

A separate `secret-scan.yaml` workflow runs the real `gitleaks` CLI against
the full git history on every push/PR, and Dependabot (`.github/dependabot.yml`)
opens version-update PRs for the Go module, the frontend's npm-managed
dependencies, and GitHub Actions themselves.

## License

MIT -- see [LICENSE](https://github.com/luiscorreiaOps/brain-agent-app/blob/main/LICENSE).
