# CODEWHY

**Understand your codebase. Discover why it is the way it is.**

CODEWHY is an AI engineering-intelligence and repository-security workspace. It connects source structure, dependency relationships, GitHub history, static security signals and Sarvam AI explanations so developers can investigate unfamiliar code and assess proposed changes with evidence.

## Product workflow

1. Connect a GitHub repository. Public repositories work without login in demo mode. With GitHub OAuth enabled, a signed-in developer can scan repositories they are authorised to access.
2. Build the engineering graph. Source files, functions, classes, imports and approximate cross-file calls are represented as graph nodes and relationships. Neo4j stores the graph when configured.
3. Investigate why. Ask CODEWHY or run the Autonomous Investigator. It retrieves likely source files, expands through imports and asks Sarvam to separate observed evidence from inference.
4. Check security. Sentinel detects credential-like strings, risky code patterns and known vulnerabilities in supported exact-version dependency manifests/lockfiles using OSV.
5. Review changes before merging. Paste a unified diff into Change Simulator or provide a GitHub PR URL to the PR Risk Reviewer.
6. Keep the trail. Investigation records and audit events are stored in SQLite. Export a repository report as JSON.

## Feature set

### Repository intelligence
- GitHub repository scanning and file explorer.
- Architecture graph for files, functions, classes, imports and approximate calls.
- Per-file GitHub commit history ("WHY HISTORY"). Commit messages are historical clues, not proof of original intent.
- Dependency impact analysis using reverse import relationships.
- Technical-debt heuristics for large files, long functions, TODO/FIXME/HACK markers and convention-based test detection.

### CODEWHY Sentinel
- Secret exposure patterns for GitHub tokens, AWS keys, Slack tokens, JWT-like values, private-key headers and hard-coded credential assignments. Secret values are masked in findings.
- Static risky-pattern checks for dynamic execution, pickle deserialization, shell execution, disabled TLS verification, unsafe YAML loading, weak hash primitives, SQL interpolation and wildcard CORS.
- Dependency inventory for pinned requirements, npm package manifests/lockfiles, Poetry/uv locks, Cargo locks and Go sums.
- Known dependency advisories via the OSV query API. Only exact versions that the scanner can identify are queried.
- Potential attack-path candidates connecting route/input-like files to risky sinks through import edges. These are graph heuristics, not data-flow or exploitability proofs.

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

Repository workspaces are namespaced by signed-in GitHub user. API routes enforce the session and repository owner when AUTH_REQUIRED=true. Sessions use HTTP-only cookies, CSRF tokens on write requests, encrypted OAuth tokens at rest, expiry and logout invalidation. Audit events cover sign-in/out, scans, security scans, investigations, change simulations and PR reviews.

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
- GET /api/auth/status, GET /api/auth/github, GET /api/auth/callback, POST /api/auth/logout — authentication.
- POST /api/repos/scan — scan a GitHub repository.
- GET /api/repos/{repo_id}/graph, GET /api/repos/{repo_id}/file, GET /api/repos/{repo_id}/history — codebase exploration.
- POST /api/repos/{repo_id}/impact — dependency impact.
- POST /api/repos/{repo_id}/ask, POST /api/repos/{repo_id}/investigate — AI Q&A and autonomous investigation.
- POST /api/repos/{repo_id}/security/scan — Sentinel scan.
- POST /api/repos/{repo_id}/change-simulate — proposed diff review.
- POST /api/repos/{repo_id}/pull-request/review — GitHub PR review.
- GET /api/repos/{repo_id}/investigations, GET /api/repos/{repo_id}/reports — history and report data.
- POST /api/voice/transcribe, POST /api/voice/speak — Sarvam voice.
- GET /api/admin/audit — admin-only audit log.

## Quality checks

~~~bash
python -m compileall -q app tests
pytest -q
~~~

GitHub Actions runs compilation, unit tests and an application import check on pushes and pull requests.

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
