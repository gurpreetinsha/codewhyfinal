# CODEWHY

**Understand your codebase. Discover why it is the way it is.**

CODEWHY is an AI engineering-intelligence and repository-security workspace. It connects source structure, dependency relationships, GitHub history, static security signals and Sarvam AI explanations so developers can investigate unfamiliar code and assess proposed changes with evidence.

## Product workflow

1. Connect a GitHub repository. With AUTH_REQUIRED=false (the development default), public repositories can be scanned without login. With GitHub OAuth enabled, a signed-in developer can scan repositories they are authorised to access.
2. Build the engineering graph. Source files, functions, classes, imports and approximate cross-file calls are represented as graph nodes and relationships. Neo4j stores the graph when configured.
3. Investigate why. Ask CODEWHY or run the Autonomous Investigator. It retrieves likely source files, expands through imports and asks Sarvam to separate observed evidence from inference.
4. Check security. Sentinel detects credential-like strings, risky code patterns and known vulnerabilities in supported exact-version dependency manifests/lockfiles using OSV.
5. Review changes before merging. Paste a unified diff into Change Simulator or provide a GitHub PR URL to the PR Risk Reviewer.
6. Keep the trail. Investigation records and audit events are stored in SQLite. Export a repository report as JSON.

## Feature set

### Repository intelligence
- GitHub repository scanning and file explorer.
- Signed-in GitHub repository browser for owned, collaborator and organisation repositories, including private repositories permitted by the user's OAuth grant.
- Architecture graph for files, functions, classes, imports and approximate calls.
- Per-file GitHub commit history ("WHY HISTORY"). Commit messages are historical clues, not proof of original intent.
- Dependency impact analysis using reverse import relationships.
- Technical-debt heuristics for large files, long functions, TODO/FIXME/HACK markers and convention-based test detection.

### CODEWHY Sentinel (Multilingual Graph Security Investigator)
- **Voice-Enabled Multilingual Investigation:** Ask security questions via microphone using Sarvam AI Speech-to-Text (`saaras:v4` in codemix mode), or type questions in English or 10+ Indian languages (Hindi, Bengali, Tamil, Telugu, Marathi, Gujarati, Kannada, Malayalam, Odia, Punjabi).
- **Multilingual Query Understanding:** Converts natural or code-mixed inquiries into structured investigation targets while strictly preserving technical identifiers (`check_password_hash`, `jwt.encode`, `/api/v1/auth/login`, `db.session.execute`).
- **Full Repository Knowledge Graph (Neo4j):** 12 node kinds (`Repository`, `File`, `Function`, `API`, `Dependency`, `Commit`, `PullRequest`, `Developer`, `Vulnerability`, `SecurityFinding`, `TechnicalDecision`, `Fix`) and 9 relationship types (`CONTAINS`, `DEFINES`, `DEPENDS_ON`, `MODIFIES`, `AFFECTS`, `INTRODUCES`, `FIXES`, `REVIEWED_IN`, `RELATED_TO`) with parameterized Cypher queries and in-memory fallback.
- **Security-Sensitive Component Identification:** Automatically catalogs authentication handlers, API endpoints, database operations, file upload mechanisms, secret management, and external service connectors.
- **Defensive Attack Path Reconstruction:** Traces multi-hop entrypoint-to-sink pathways with explicit confidence levels: `VERIFIED` (source-proven call/import chain), `POTENTIAL` (structural or import connection), and `AI_HYPOTHESIS` (inferred risk). Read-only and non-intrusive.
- **Evidence-Backed Findings & Grounding:** Findings cite concrete file paths, line ranges, AST symbols, and commit metadata. Flags unverified assertions explicitly with *"Insufficient repository evidence to verify this finding."*
- **Interactive Remediation Tracking:** Developers can inspect, review, and toggle lifecycle statuses (`open`, `under_review`, `fixed`, `verified`) persisted in SQLite with full audit records.
- **Multilingual Spoken Explanations:** Sarvam Text-to-Speech (`bulbul:v4-flash`) provides on-demand spoken summaries with native audio playback controls.
- **Secret exposure patterns:** GitHub tokens, AWS keys, Slack tokens, JWT-like values, private-key headers, and hard-coded credential assignments (with automatic masking).
- **Static risky-pattern checks:** Dynamic execution, pickle deserialization, shell execution, disabled TLS verification, unsafe YAML loading, weak hash primitives, SQL interpolation, and wildcard CORS.
- **Dependency inventory & OSV advisories:** Direct integration with OSV database for pinned requirements, npm manifests, Poetry/uv, Cargo, and Go sum lockfiles.

### Sentinel Code Helper
- Select any file from the currently scanned GitHub repository and request a focused code review.
- Combines existing static security-pattern signals with a Sarvam-powered review for correctness, edge cases, security and maintainability.
- Returns issue explanations and a complete suggested replacement file. The replacement stays editable in the browser.
- Shows an approximate diff before the developer explicitly confirms the commit.
- Commits the reviewed replacement to a newly created `codewhy/*` branch, never directly to the default branch. The helper checks the live file against the scanned snapshot to avoid committing over concurrent changes, and provides a GitHub compare link to open a pull request.
- Requires GitHub sign-in and write permission for the repository. Demo workspaces cannot be committed. The source file is not sent to the model when local secret redaction detects credential-like values; remove or rotate secrets before requesting an AI replacement.
- Suggested code is not automatically tested. Review it and run the project checks before opening or merging a pull request.

### AI investigation and change review
- Ask your codebase using Sarvam Chat Completions.
- Autonomous Investigator with retrieval, graph expansion, evidence references, investigation steps and a traceability status.
- Change Simulator for unified diffs, dependency impact and security pattern triage.
- PR Risk Reviewer for GitHub pull-request patches, changed files and static risk signals.
- Investigation history and JSON repository reports.
- Sarvam Saaras v4 speech-to-text for short voice questions (30-second API limit) and Bulbul v4 Flash text-to-speech for spoken answers.

## Technology

- Frontend: responsive HTML/CSS/JavaScript workspace.
- Backend: Python 3.12, FastAPI, Uvicorn.
- Graph: Neo4j Python driver; in-memory graph for the demo/fallback.
- AI: Sarvam Chat Completions (sarvam-105b by default), Saaras v4 STT, Bulbul v4 Flash TTS.
- Security intelligence: local static patterns plus OSV advisories.
- Identity and persistence: GitHub OAuth, encrypted server-side OAuth tokens, SQLite sessions/audit/investigation records.
- Deployment: Docker and Docker Compose.

## Quick start

### Docker

~~~bash
cp .env.example .env
# Add SARVAM_API_KEY and optional Neo4j credentials
docker compose up --build
~~~

Open http://localhost:8000 and choose Load demo.

### Vercel

The FastAPI application is exported from `app/index.py`, which is a Vercel-supported FastAPI entry point. Connect this repository to Vercel and keep the project **Root Directory** set to the repository root. Vercel detects the FastAPI app automatically; no custom build command or rewrite file is required.

For a public-repository hackathon demo, configure these Project → Settings → Environment Variables:

- `SARVAM_API_KEY`: enables live code explanations, investigations and voice features.
- `AUTH_REQUIRED`: leave `false` for the no-login public-repository demo.
- `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`: optional; without them the graph uses the in-memory fallback.

Redeploy after changing environment variables. Check `/api/health` after deployment to see which integrations are configured.

**Vercel demo limitation:** Vercel's writable `/tmp` directory is used for SQLite, but it is temporary and local to an individual function instance. Repository snapshots and graph fallback are also held in process memory. This is acceptable for a single-instance demo flow, but scans, sessions and history are not durable across cold starts or multiple instances. Do not enable authenticated multi-user/private-repository use or treat this as production storage until shared persistent database and source storage are configured. For durable hackathon judging/demo data, use the Docker deployment with a persistent `./data` volume and a configured Neo4j instance.

### Local Python

Requires Python 3.11+.

~~~bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
~~~

## Environment variables

| Variable | Required | Description |
|---|---|---|
| SARVAM_API_KEY | For live AI and voice | Sarvam API subscription key |
| SARVAM_MODEL | No | Defaults to sarvam-105b |
| SARVAM_API_BASE | No | Defaults to https://api.sarvam.ai/v2 |
| NEO4J_URI | For persistent graph | Aura URI, e.g. neo4j+s://xxxx.databases.neo4j.io |
| NEO4J_USERNAME | For Neo4j | Usually neo4j |
| NEO4J_PASSWORD | For Neo4j | Database password |
| NEO4J_DATABASE | No | Defaults to neo4j |
| GITHUB_OAUTH_CLIENT_ID | For sign-in | GitHub OAuth App client ID |
| GITHUB_OAUTH_CLIENT_SECRET | For sign-in | GitHub OAuth App client secret |
| GITHUB_OAUTH_REDIRECT_URI | For sign-in | Exact callback URL ending in /api/auth/callback |
| SESSION_SECRET | For OAuth | At least 32 random characters; also encrypts stored OAuth tokens |
| AUTH_REQUIRED | Recommended true for internet deployment | Enforces sign-in, CSRF checks and repository ownership checks |
| ADMIN_GITHUB_USERS | Optional | Comma-separated GitHub logins granted admin role |
| REVIEWER_GITHUB_USERS | Optional | Comma-separated GitHub logins granted reviewer role |
| DATABASE_PATH | No | Defaults to ./data/codewhy.sqlite3; Compose uses /data/codewhy.sqlite3 |
| CORS_ORIGINS | No | Comma-separated allowed origins; leave empty for same-origin |
| MAX_REPO_FILES | No | Maximum files per scan; defaults to 350 |

Generate a session secret:

~~~bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
~~~

## GitHub OAuth setup

1. Create a GitHub OAuth App in GitHub Developer Settings.
2. Set the Authorization callback URL to https://YOUR_DOMAIN/api/auth/callback.
3. Add the client ID, client secret and exact redirect URL to your deployment environment.
4. Set a strong SESSION_SECRET and set AUTH_REQUIRED=true.
5. Add GitHub usernames to ADMIN_GITHUB_USERS and REVIEWER_GITHUB_USERS as needed.

The current OAuth flow requests read:user user:email repo so users can scan private repositories available to their GitHub account. GitHub's OAuth repo scope is broad; review the permission prompt carefully. For a production enterprise rollout, prefer a GitHub App with narrowly scoped read-only repository permissions and an organisation installation/approval policy.

Roles:
- Developer: scan and investigate their own connected repository workspaces.
- Reviewer: developer capabilities plus pull-request review.
- Admin: reviewer capabilities plus audit-event access.

Repository workspaces are namespaced by signed-in GitHub user. API routes enforce the session and repository owner when AUTH_REQUIRED=true. Sessions use HTTP-only cookies, CSRF tokens on write requests, encrypted OAuth tokens at rest, expiry and logout invalidation. Local logout clears the stored token when the user's last session ends; revoke the OAuth App in GitHub Settings → Applications to revoke the provider-side grant. Audit events cover sign-in/out, scans, security scans, investigations, change simulations and PR reviews.

## Sarvam integration

CODEWHY uses Sarvam's OpenAI-compatible Chat Completions API at POST /v2/chat/completions with the api-subscription-key header. The default model is sarvam-105b.

Voice:
- STT: POST https://api.sarvam.ai/speech-to-text, model saaras:v4, codemix mode by default. The synchronous endpoint accepts audio up to 30 seconds.
- TTS: POST https://api.sarvam.ai/text-to-speech, model bulbul:v4-flash.

The browser never receives the Sarvam API key; voice requests are proxied through the backend.

## Neo4j integration

The app persists repository, file, function and class nodes plus CONTAINS, DEFINES, IMPORTS and CALLS relationships. Node IDs are namespaced by repository workspace to prevent same-path files from different users/repositories colliding. A rescan removes the old file/function/class subgraph before writing the refreshed graph.

If Neo4j is not configured, the demo uses an in-memory graph. The SQLite database stores user sessions, encrypted GitHub OAuth tokens, audit events and investigation records; source snapshots remain in application memory and must be rescanned after a process restart.

## API overview

- GET /api/health — integration status.
- GET /api/auth/status, GET /api/auth/github, GET /api/auth/callback, POST /api/auth/logout — authentication; GET /api/github/repos — signed-in user's accessible repositories.
- POST /api/repos/scan — scan a GitHub repository.
- GET /api/repos/{repo_id}/graph, GET /api/repos/{repo_id}/file, GET /api/repos/{repo_id}/history — codebase exploration.
- POST /api/repos/{repo_id}/impact — dependency impact.
- POST /api/repos/{repo_id}/ask, POST /api/repos/{repo_id}/investigate — AI Q&A and autonomous investigation.
- POST /api/repos/{repo_id}/security/scan and GET /api/repos/{repo_id}/security-history — Sentinel scan and finding timeline.
- GET /api/sentinel/languages — Supported languages and Sarvam voice mappings.
- GET /api/sentinel/repos — Repositories accessible to the logged-in user for Sentinel.
- POST /api/sentinel/understand-query — Multilingual security query parsing and technical identifier extraction.
- POST /api/sentinel/investigate — Full graph-powered, evidence-backed security investigation.
- GET /api/sentinel/history — Persisted Sentinel investigation logs.
- GET /api/sentinel/investigation/{id} — Retrieve detailed investigation record and findings.
- PATCH /api/sentinel/finding/{finding_id}/status — Update finding lifecycle status (open, under_review, fixed, verified).
- POST /api/sentinel/speak — Generate Sarvam Bulbul TTS spoken response.
- GET /api/sentinel/overview/{repo_id} — Graph topology and security component statistics.
- POST /api/repos/{repo_id}/change-simulate — proposed diff review.
- POST /api/repos/{repo_id}/pull-request/review — GitHub PR review.
- GET /api/repos/{repo_id}/investigations, GET /api/repos/{repo_id}/reports — history and report data.
- POST /api/voice/transcribe, POST /api/voice/speak — Sarvam voice.
- GET /api/admin/audit — admin-only audit log.

## Quality checks

~~~bash
python -m compileall -q app tests
python -m pytest -q
~~~

GitHub Actions runs Python compilation, unit tests, frontend JavaScript syntax validation, a Docker image build and an application import check on pushes and pull requests.

## Data handling and privacy

- Repository contents are fetched from GitHub using the signed-in user's OAuth token. Unauthenticated mode can scan public repositories only.
- Ask Why and Autonomous Investigator send selected source excerpts and graph context to Sarvam AI. Credential-like values and PEM private-key blocks are redacted before AI requests and saved evidence. Voice recordings are sent to Sarvam speech-to-text. Use these features only where your organisation permits that processing.
- Dependency package names and exact versions are sent to the public OSV API for advisory lookup.
- Neo4j stores repository identifiers, file paths, symbol names and relationship edges; it does not store full source file bodies.
- Investigation records in SQLite include the question, answer, evidence excerpts and file references. Security scan history stores finding snapshots and tracks newly detected, unchanged and resolved findings. OAuth tokens are encrypted at rest using a key derived from SESSION_SECRET. Protect the SQLite volume and Neo4j database as sensitive company data.
- The current build has no self-service investigation deletion or configurable retention policy. Add both before handling regulated or highly sensitive repositories.

## Important limitations and production checklist

CODEWHY is a hackathon-stage engineering assistant, not a certified security scanner or production enterprise security boundary.

- Source parsing is lightweight: Python uses the AST; JS/TS/Go/Java/Rust symbol extraction uses regex heuristics. Dynamic imports, reflection, runtime wiring and call semantics may be missed.
- Dependency advisories require an exact version and an OSV response. Unsupported manifests, ranges and private registries may be omitted. An empty result is not a clean bill of health.
- Security patterns can produce false positives and false negatives. No taint analysis, exploit execution, container scanning or dynamic application testing is performed.
- Potential attack paths are import-connected route/sink candidates, not proof of attacker-controlled data reaching a sink.
- Change simulation and PR review do not execute tests, run builds, merge PRs or apply patches.
- Answer verification checks whether retrieved file paths are referenced; it does not mathematically validate every model claim.
- Source snapshots are held in process memory; use one application worker unless you add shared persistent source storage and a distributed job/session design.
- The current OAuth app requests broad repo scope for private repository access. Use a least-privilege GitHub App before enterprise deployment.
- Before production rollout, add organisation allowlists/SSO, stronger tenant isolation, a GitHub App installation flow, persistent source/object storage, distributed rate limiting, observability, backup/restore, retention controls, and a formal security review.

Never commit .env, OAuth secrets, API keys, private keys or repository source snapshots.

## License

MIT
