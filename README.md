# CODEWHY

**Understand your codebase. Discover why it is the way it is.**

CODEWHY is an AI-powered codebase intelligence platform for engineering teams. It maps source-code relationships into a Neo4j knowledge graph and uses Sarvam AI to explain architecture, answer repository questions, surface technical debt, and reason about change impact.

## Features

- **Repository scan:** import a public GitHub repository (or a private one with a GitHub token).
- **Knowledge graph:** files, functions, classes, imports, calls, commits, and tests represented as Neo4j nodes and relationships.
- **Ask your codebase:** grounded answers from retrieved repository evidence using Sarvam Chat Completions.
- **Architecture explorer:** interactive dependency graph.
- **Technical debt radar:** heuristic findings for long files/functions, TODOs, missing tests, and dependency hotspots.
- **Change impact:** inspect downstream dependencies before editing a file.
- **Demo mode:** explore a bundled sample codebase without credentials.

## Quick start (Docker)

1. Copy `.env.example` to `.env`.
2. Add your Sarvam API key and Neo4j credentials (optional for demo mode; recommended for full graph persistence).
3. Run:

```bash
docker compose up --build
```

Open http://localhost:8000.

## Run locally

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SARVAM_API_KEY` | For live AI | Sarvam API subscription key |
| `SARVAM_MODEL` | No | Defaults to `sarvam-105b` |
| `SARVAM_API_BASE` | No | Defaults to `https://api.sarvam.ai/v2` |
| `NEO4J_URI` | For persistent graph | Aura URI, e.g. `neo4j+s://xxxx.databases.neo4j.io` |
| `NEO4J_USERNAME` | For persistent graph | Usually `neo4j` |
| `NEO4J_PASSWORD` | For persistent graph | Database password |
| `NEO4J_DATABASE` | No | Defaults to `neo4j` |
| `GITHUB_TOKEN` | Private repositories | Fine-grained token with read-only Contents and Metadata access |
| `APP_SECRET` | Production | Long random secret used for session signing |
| `CORS_ORIGINS` | No | Comma-separated allowed origins; defaults to same-origin |
| `MAX_REPO_FILES` | No | Maximum files per scan; defaults to 350 |

The app starts without external credentials. In that mode, demo data and local in-memory graph storage are available. Live Sarvam answers require `SARVAM_API_KEY`; persistent graph storage requires Neo4j credentials.

## Sarvam integration

CODEWHY calls Sarvam's OpenAI-compatible Chat Completions API at `POST /v2/chat/completions` with the `api-subscription-key` header. The default model is `sarvam-105b`. You can set another model supported by your Sarvam account through `SARVAM_MODEL`.

## Neo4j integration

The app uses the official Neo4j Python driver. It creates `Repository`, `File`, `Function`, `Class`, and `Commit` nodes and relationships such as `CONTAINS`, `DEFINES`, `IMPORTS`, `CALLS`, and `MODIFIED`. Repository IDs are namespaced to prevent accidental cross-repository mixing.

## Deploy

Deploy with Docker on any container host (Render, Railway, Fly.io, Azure Container Apps, AWS App Runner, etc.). Set the environment variables from `.env.example`, expose port `8000`, and use `/api/health` as the health check.

For production:
- Use a managed Neo4j Aura instance and a persistent secret manager.
- Set a strong `APP_SECRET`.
- Use a private GitHub App or fine-grained read-only token for private repositories.
- Put the app behind HTTPS.
- Restrict CORS to your frontend origin.
- Review your organisation's source-code data handling requirements before connecting proprietary repositories.

## Security notes

- Repository content is treated as untrusted input; it is never executed.
- GitHub tokens and Sarvam keys are read only from server environment variables.
- API responses do not expose secrets.
- This hackathon build is a single-workspace prototype. Add organisation SSO, role-based access, audit logs, rate limiting, and per-tenant encryption before production enterprise rollout.

## Project structure

```
app/
  main.py             FastAPI routes and app startup
  config.py           Environment configuration
  services/
    github.py         GitHub repository ingestion
    parser.py         Lightweight source-code relationship extraction
    graph.py          Neo4j + in-memory graph adapter
    sarvam.py         Sarvam chat completion client
    analyzer.py       Technical debt and impact analysis
static/
  index.html          Responsive single-page application
Dockerfile
docker-compose.yml
requirements.txt
.env.example
```

## License

MIT
