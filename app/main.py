from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
import secrets
from collections import Counter, defaultdict
from pathlib import PurePosixPath
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.security import security_report, scan_source
from app.auth import (AUTH_REQUIRED, CSRF_COOKIE, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI, SESSION_COOKIE, audit, audit_list, create_session, delete_session, get_session, init_auth_db, load_investigations, oauth_ready, save_investigation, valid_csrf)

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None

load_dotenv()

APP_NAME = "CODEWHY"
SARVAM_API_KEY = os.getenv("SARVAM_API_KEY", "")
SARVAM_MODEL = os.getenv("SARVAM_MODEL", "sarvam-105b")
SARVAM_API_BASE = os.getenv("SARVAM_API_BASE", "https://api.sarvam.ai/v2").rstrip("/")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "350"))
NEO4J_URI = os.getenv("NEO4J_URI", "")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

app = FastAPI(title="CODEWHY API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

driver = None
if NEO4J_URI and NEO4J_PASSWORD and GraphDatabase:
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        driver.verify_connectivity()
    except Exception as exc:
        print(f"[CODEWHY] Neo4j unavailable; using memory graph: {exc}")
        driver = None

# In-memory fallback keeps the product usable for a zero-credential demo.
REPOS: dict[str, dict[str, Any]] = {}
INVESTIGATIONS: dict[str, list[dict[str, Any]]] = defaultdict(list)
REPO_OWNERS: dict[str, str] = {}
OAUTH_STATES: dict[str, int] = {}
init_auth_db()
if AUTH_REQUIRED and not oauth_ready():
    raise RuntimeError("AUTH_REQUIRED=true needs GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, GITHUB_OAUTH_REDIRECT_URI, and SESSION_SECRET (32+ characters).")

DEMO_FILES = {
    "README.md": "# Atlas Commerce\nA small commerce API demo.\n",
    "src/orders/service.py": "from src.payments.gateway import charge\nfrom src.orders.repository import save_order\n\ndef create_order(user_id, items):\n    total = sum(item['price'] for item in items)\n    payment = charge(user_id, total)\n    return save_order(user_id, items, payment)\n",
    "src/payments/gateway.py": "def charge(user_id, amount):\n    # TODO: add idempotency key before production rollout\n    return {'user_id': user_id, 'amount': amount, 'status': 'authorized'}\n",
    "src/orders/repository.py": "def save_order(user_id, items, payment):\n    return {'id': 'ord_demo_001', 'user_id': user_id, 'items': items, 'payment': payment}\n",
    "src/notifications/email.py": "def send_order_confirmation(order):\n    return True\n",
    "tests/test_orders.py": "def test_create_order_persists_payment():\n    assert True\n",
    "src/legacy/pricing.py": "def calculate_discount(customer, total):\n    if customer.get('tier') == 'gold':\n        return total * 0.2\n    return 0\n",
}

def rid(owner: str, name: str) -> str:
    return f"{owner}/{name}"

def _parse_file(path: str, content: str) -> dict[str, Any]:
    ext = PurePosixPath(path).suffix.lower()
    result = {"path": path, "language": "python" if ext == ".py" else "javascript" if ext in {".js", ".jsx"} else "typescript" if ext in {".ts", ".tsx"} else "text", "functions": [], "classes": [], "imports": [], "calls": [], "lines": len(content.splitlines()), "todo": len(re.findall(r"TODO|FIXME|HACK", content, re.I)), "content": content[:12000]}
    if ext == ".py":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    result["functions"].append({"name": node.name, "line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno), "args": len(node.args.args)})
                elif isinstance(node, ast.ClassDef):
                    result["classes"].append({"name": node.name, "line": node.lineno})
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names]
                    result["imports"].extend(names if isinstance(node, ast.Import) else [node.module or ""])
                elif isinstance(node, ast.Call):
                    fn = node.func
                    name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                    if name:
                        result["calls"].append(name)
        except SyntaxError:
            result["parse_error"] = True
    else:
        result["functions"] = [{"name": n, "line": i + 1, "end_line": i + 1, "args": 0} for i, n in enumerate(re.findall(r"(?:function|const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*)?(?:async\s*)?\(", content))]
        result["classes"] = [{"name": n, "line": i + 1} for i, n in enumerate(re.findall(r"class\s+([A-Za-z_$][\w$]*)", content))]
        result["imports"] = re.findall(r"(?:from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\))", content)
        result["imports"] = [x[0] or x[1] for x in result["imports"]]
    return result

def _resolve_import(source: str, module: str, known: set[str]) -> str | None:
    if not module or module.startswith((".", "/")):
        candidate = str(PurePosixPath(source).parent / module)
        for suffix in (".py", ".js", ".ts", ".tsx", ".jsx", "/index.ts", "/index.js"):
            p = str(PurePosixPath(candidate + suffix))
            if p in known:
                return p
    normalized = module.replace(".", "/")
    for p in known:
        if p.endswith(normalized + ".py") or p.endswith(normalized + "/index.ts") or p.endswith(normalized + ".ts"):
            return p
    return None

def build_graph(repo_id: str, files: dict[str, str], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    parsed = {p: _parse_file(p, c) for p, c in files.items()}
    known = set(parsed)
    nodes, edges = [], []
    file_to_functions: dict[str, list[str]] = defaultdict(list)
    for path, info in parsed.items():
        fid = f"file:{path}"
        nodes.append({"id": fid, "label": PurePosixPath(path).name, "type": "file", "path": path, "language": info["language"], "lines": info["lines"]})
        for fn in info["functions"]:
            nid = f"fn:{path}:{fn['name']}"
            file_to_functions[path].append(nid)
            nodes.append({"id": nid, "label": fn["name"], "type": "function", "path": path, "line": fn["line"], "args": fn["args"]})
            edges.append({"source": fid, "target": nid, "type": "DEFINES"})
        for cls in info["classes"]:
            nid = f"class:{path}:{cls['name']}"
            nodes.append({"id": nid, "label": cls["name"], "type": "class", "path": path, "line": cls["line"]})
            edges.append({"source": fid, "target": nid, "type": "DEFINES"})
    for path, info in parsed.items():
        for module in info["imports"]:
            target = _resolve_import(path, module, known)
            if target and target != path:
                edges.append({"source": f"file:{path}", "target": f"file:{target}", "type": "IMPORTS"})
    # Approximate call links across known function names; marked as syntactic evidence.
    function_index = defaultdict(list)
    for path, info in parsed.items():
        for fn in info["functions"]:
            function_index[fn["name"]].append((path, fn))
    for path, info in parsed.items():
        for call in set(info["calls"]):
            for target_path, fn in function_index.get(call, []):
                if target_path != path:
                    edges.append({"source": f"file:{path}", "target": f"fn:{target_path}:{call}", "type": "CALLS"})
    stats = {
        "files": len(parsed),
        "functions": sum(len(x["functions"]) for x in parsed.values()),
        "classes": sum(len(x["classes"]) for x in parsed.values()),
        "imports": sum(1 for e in edges if e["type"] == "IMPORTS"),
        "todos": sum(x["todo"] for x in parsed.values()),
        "lines": sum(x["lines"] for x in parsed.values()),
        "languages": dict(Counter(x["language"] for x in parsed.values())),
    }
    return {"id": repo_id, "files": parsed, "nodes": nodes, "edges": edges, "stats": stats, "metadata": metadata or {}, "scanned_at": int(time.time())}

def persist_graph(graph: dict[str, Any]) -> None:
    if not driver:
        return
    repo_id = graph["id"]
    driver.execute_query("MERGE (r:Repository {id:$id}) SET r.name=$name, r.scanned_at=$scanned_at", id=repo_id, name=graph["metadata"].get("full_name", repo_id), scanned_at=graph["scanned_at"], database_=NEO4J_DATABASE)
    driver.execute_query("MATCH (r:Repository {id:$id}) OPTIONAL MATCH (r)-[rel:CONTAINS]->(f:File) DETACH DELETE f", id=repo_id, database_=NEO4J_DATABASE)
    for node in graph["nodes"]:
        if node["type"] == "file":
            driver.execute_query("MATCH (r:Repository {id:$repo}) MERGE (f:File {id:$id}) SET f.path=$path, f.label=$label, f.language=$language, f.lines=$lines MERGE (r)-[:CONTAINS]->(f)", repo=repo_id, id=node["id"], path=node["path"], label=node["label"], language=node["language"], lines=node["lines"], database_=NEO4J_DATABASE)
        else:
            label = "Function" if node["type"] == "function" else "CodeClass"
            driver.execute_query(f"MATCH (r:Repository {{id:$repo}})-[:CONTAINS]->(f:File {{path:$path}}) MERGE (n:{label} {{id:$id}}) SET n.name=$name, n.line=$line MERGE (f)-[:DEFINES]->(n)", repo=repo_id, path=node["path"], id=node["id"], name=node["label"], line=node.get("line", 0), database_=NEO4J_DATABASE)
    for edge in graph["edges"]:
        if edge["type"] == "IMPORTS":
            driver.execute_query("MATCH (a:File {id:$source}), (b:File {id:$target}) MERGE (a)-[:IMPORTS]->(b)", source=edge["source"], target=edge["target"], database_=NEO4J_DATABASE)
        elif edge["type"] == "CALLS":
            driver.execute_query("MATCH (a:File {id:$source}), (b:Function {id:$target}) MERGE (a)-[:CALLS]->(b)", source=edge["source"], target=edge["target"], database_=NEO4J_DATABASE)

def graph_view(graph: dict[str, Any]) -> dict[str, Any]:
    return {"nodes": graph["nodes"][:180], "edges": graph["edges"][:300], "files": {p: {"lines": info["lines"], "language": info["language"]} for p, info in graph["files"].items()}, "stats": graph["stats"], "metadata": graph["metadata"], "scanned_at": graph["scanned_at"]}

def debt_report(graph: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for path, info in graph["files"].items():
        if info["lines"] > 350:
            out.append({"severity": "high", "title": "Large source file", "path": path, "detail": f"{info['lines']} lines. Consider splitting by responsibility.", "evidence": f"{info['lines']} lines"})
        if info["todo"]:
            out.append({"severity": "medium", "title": "Unresolved work markers", "path": path, "detail": f"{info['todo']} TODO/FIXME/HACK marker(s) found.", "evidence": f"{info['todo']} marker(s)"})
        for fn in info["functions"]:
            size = fn["end_line"] - fn["line"] + 1
            if size > 65:
                out.append({"severity": "medium", "title": "Long function", "path": path, "detail": f"{fn['name']} spans {size} lines.", "evidence": f"Lines {fn['line']}–{fn['end_line']}"})
        if path.startswith("src/") and "test" not in path.lower() and info["functions"] and not any(path.replace("src/", "tests/").split(".")[0] in t for t in graph["files"] if "test" in t.lower()):
            out.append({"severity": "low", "title": "Test coverage not detected", "path": path, "detail": "No convention-matched test file was detected. This is a heuristic, not proof of missing tests.", "evidence": "Path-based heuristic"})
    return out[:80]

def impact_report(graph: dict[str, Any], path: str) -> dict[str, Any]:
    if path not in graph["files"]:
        raise HTTPException(404, "File not found in scanned repository")
    reverse = defaultdict(set)
    for e in graph["edges"]:
        if e["type"] == "IMPORTS":
            reverse[e["target"].removeprefix("file:")].add(e["source"].removeprefix("file:"))
    seen, queue = set(), [path]
    while queue:
        cur = queue.pop(0)
        for parent in reverse.get(cur, set()):
            if parent not in seen and parent != path:
                seen.add(parent)
                queue.append(parent)
    return {"path": path, "direct_dependents": sorted(reverse.get(path, set())), "transitive_dependents": sorted(seen), "count": len(seen), "note": "Impact is inferred from statically detected import relationships; dynamic imports and runtime behaviour may not be represented."}

async def github_files(owner: str, repo: str, branch: str | None = None, token: str | None = None) -> tuple[dict[str, str], dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
        meta_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        if meta_resp.status_code == 404:
            raise HTTPException(404, "Repository not found or not accessible. Add a GitHub token for private repositories.")
        if meta_resp.status_code >= 400:
            raise HTTPException(meta_resp.status_code, "GitHub repository lookup failed")
        meta = meta_resp.json()
        ref = branch or meta["default_branch"]
        tree_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}", params={"recursive": "1"})
        if tree_resp.status_code >= 400:
            raise HTTPException(tree_resp.status_code, "Could not read repository tree")
        tree = tree_resp.json().get("tree", [])
        candidates = [x for x in tree if x.get("type") == "blob" and PurePosixPath(x["path"]).suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rs", ".md"} and not any(part in {".git", "node_modules", "vendor", "dist", "build", ".next"} for part in x["path"].split("/"))]
        candidates = candidates[:MAX_REPO_FILES]
        files: dict[str, str] = {}
        sem = __import__("asyncio").Semaphore(12)
        async def fetch(item):
            async with sem:
                url = item.get("url")
                if not url:
                    return
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                data = resp.json()
                if data.get("encoding") == "base64" and data.get("size", 0) < 180_000:
                    import base64
                    try:
                        files[item["path"]] = base64.b64decode(data["content"]).decode("utf-8", "replace")
                    except Exception:
                        pass
        await __import__("asyncio").gather(*(fetch(x) for x in candidates))
        if not files:
            raise HTTPException(422, "No supported source files found in this repository.")
        return files, {"full_name": meta["full_name"], "description": meta.get("description") or "", "default_branch": meta["default_branch"], "html_url": meta["html_url"], "stars": meta.get("stargazers_count", 0), "private": meta.get("private", False), "files_loaded": len(files), "files_limit": MAX_REPO_FILES}

class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=500)
    branch: str | None = None

class AskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=2000)

class ImpactRequest(BaseModel):
    path: str

class InvestigationRequest(BaseModel):
    question: str = Field(min_length=5, max_length=2000)

class ChangeSimulationRequest(BaseModel):
    description: str = Field(min_length=5, max_length=2000)
    diff: str = Field(min_length=5, max_length=100000)

class PullRequestReviewRequest(BaseModel):
    url: str = Field(min_length=15, max_length=500)

@app.middleware("http")
async def auth_and_tenant_middleware(request: Request, call_next):
    path = request.url.path
    sid = request.cookies.get(SESSION_COOKIE, "")
    user = get_session(sid) if sid else None
    request.state.user = user
    public_paths = {"/api/health", "/api/auth/status", "/api/auth/github", "/api/auth/callback"}
    if AUTH_REQUIRED and path.startswith("/api/") and path not in public_paths:
        if not user:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Sign in with GitHub to access this workspace."}, status_code=401)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            csrf = request.headers.get("X-CSRF-Token", "")
            if not valid_csrf(user, csrf):
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "CSRF validation failed. Refresh and try again."}, status_code=403)
        for repo_id, owner in REPO_OWNERS.items():
            if path.startswith("/api/repos/" + repo_id + "/") and owner.lower() != user["login"].lower():
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "Repository access denied."}, status_code=404)
    response = await call_next(request)
    return response

@app.get("/api/auth/status")
async def auth_status(request: Request):
    user = getattr(request.state, "user", None)
    return {"auth_required": AUTH_REQUIRED, "oauth_configured": oauth_ready(), "authenticated": bool(user), "user": ({ "login": user["login"], "avatar_url": user["avatar_url"], "role": user["role"] } if user else None), "csrf_token": request.cookies.get(CSRF_COOKIE, "")}

@app.get("/api/auth/github")
async def github_oauth_start():
    if not oauth_ready():
        raise HTTPException(503, "GitHub OAuth is not configured. Set the OAuth environment variables first.")
    state = secrets.token_urlsafe(32)
    OAUTH_STATES[state] = int(time.time()) + 600
    for old, expiry in list(OAUTH_STATES.items()):
        if expiry < int(time.time()):
            OAUTH_STATES.pop(old, None)
    from urllib.parse import urlencode
    params = urlencode({"client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI, "scope": "read:user user:email repo", "state": state})
    return RedirectResponse("https://github.com/login/oauth/authorize?" + params, status_code=302)

@app.get("/api/auth/callback")
async def github_oauth_callback(code: str, state: str):
    expiry = OAUTH_STATES.pop(state, None)
    if not expiry or expiry < int(time.time()):
        raise HTTPException(400, "OAuth state expired or invalid. Please sign in again.")
    async with httpx.AsyncClient(timeout=20) as client:
        token_response = await client.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, json={"client_id": OAUTH_CLIENT_ID, "client_secret": OAUTH_CLIENT_SECRET, "code": code, "redirect_uri": OAUTH_REDIRECT_URI})
        if token_response.status_code >= 400:
            raise HTTPException(502, "GitHub token exchange failed.")
        access_token = token_response.json().get("access_token")
        if not access_token:
            raise HTTPException(401, "GitHub did not issue an access token.")
        profile_response = await client.get("https://api.github.com/user", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"})
        if profile_response.status_code >= 400:
            raise HTTPException(502, "Could not retrieve the GitHub profile.")
        profile = profile_response.json()
    sid, csrf = create_session(profile, access_token)
    user = {"id": profile["id"], "login": profile["login"]}
    audit(user, "auth.login", "", "GitHub OAuth")
    response = RedirectResponse("/", status_code=302)
    secure = OAUTH_REDIRECT_URI.startswith("https://")
    response.set_cookie(SESSION_COOKIE, sid, httponly=True, secure=secure, samesite="lax", max_age=43200, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="lax", max_age=43200, path="/")
    return response

@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    user = getattr(request.state, "user", None)
    delete_session(request.cookies.get(SESSION_COOKIE, ""))
    audit(user, "auth.logout")
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response

@app.get("/api/admin/audit")
async def get_audit(request: Request, limit: int = 100):
    user = getattr(request.state, "user", None)
    if not user or user["role"] != "admin":
        raise HTTPException(403, "Administrator role required.")
    return {"events": audit_list(limit)}

@app.get("/api/health")
async def health():
    return {"status": "ok", "sarvam_configured": bool(SARVAM_API_KEY), "neo4j_connected": bool(driver), "github_token_configured": bool(GITHUB_TOKEN)}

@app.get("/api/demo")
async def demo():
    graph = build_graph("demo/atlas-commerce", DEMO_FILES, {"full_name": "atlas-commerce/demo", "description": "A sample commerce backend with orders, payments, and a legacy pricing module.", "default_branch": "main", "html_url": "https://github.com", "demo": True})
    REPOS[graph["id"]] = graph
    return {"repository": graph_view(graph), "debt": debt_report(graph), "id": graph["id"]}

@app.post("/api/repos/scan")
async def scan(req: ScanRequest, request: Request):
    match = re.match(r"^(?:https?://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", req.url.strip())
    if not match:
        raise HTTPException(400, "Enter a GitHub repository URL like https://github.com/owner/repo")
    owner, repo = match.groups()
    user = getattr(request.state, "user", None)\n    files, meta = await github_files(owner, repo, req.branch, user.get("access_token") if user else None)
    graph = build_graph(rid(owner, repo), files, meta)
    REPOS[graph["id"]] = graph
    try:
        persist_graph(graph)
    except Exception as exc:
        print(f"[CODEWHY] Graph persistence failed: {exc}")
    return {"repository": graph_view(graph), "debt": debt_report(graph), "id": graph["id"], "storage": "neo4j" if driver else "memory"}

@app.get("/api/repos")
async def repos():
    return [{"id": g["id"], "metadata": g["metadata"], "stats": g["stats"]} for g in REPOS.values()]

@app.get("/api/repos/{repo_id:path}/graph")
async def get_graph(repo_id: str):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository has not been scanned in this app session")
    return graph_view(graph)

@app.get("/api/repos/{repo_id:path}/debt")
async def get_debt(repo_id: str):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found")
    return debt_report(graph)

@app.post("/api/repos/{repo_id:path}/impact")
async def get_impact(repo_id: str, req: ImpactRequest):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found")
    return impact_report(graph, req.path)

async def sarvam_answer(question: str, context: str) -> tuple[str, str]:
    if not SARVAM_API_KEY:
        return ("Sarvam AI is not configured yet. Add SARVAM_API_KEY to your deployment environment to enable live answers. The repository evidence is ready and shown alongside this response.", "not_configured")
    system = """You are CODEWHY, a careful staff-level software architect. Answer only from the supplied repository evidence. Clearly distinguish direct evidence from inference. Never invent business intent, runtime behaviour, commit history, tests, or ownership. If the evidence is insufficient, say what is unknown and what additional evidence would establish it. Cite file paths and line numbers where available. Be concise but useful."""
    async with httpx.AsyncClient(timeout=75) as client:
        try:
            response = await client.post(f"{SARVAM_API_BASE}/chat/completions", headers={"api-subscription-key": SARVAM_API_KEY, "Content-Type": "application/json"}, json={"model": SARVAM_MODEL, "messages": [{"role": "system", "content": system}, {"role": "user", "content": f"QUESTION:\n{question}\n\nREPOSITORY EVIDENCE:\n{context}"}], "temperature": 0.2, "max_tokens": 1200})
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"], "sarvam"
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:500]
            raise HTTPException(502, f"Sarvam API returned {exc.response.status_code}: {detail}")
        except (httpx.RequestError, KeyError, IndexError, ValueError) as exc:
            raise HTTPException(502, f"Sarvam request failed: {exc}")

@app.post("/api/repos/{repo_id:path}/ask")
async def ask(repo_id: str, req: AskRequest):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")
    q = req.question.lower()
    scored = []
    for path, info in graph["files"].items():
        haystack = (path + " " + info["content"]).lower()
        terms = [t for t in re.findall(r"[a-z_]{3,}", q) if t not in {"what", "why", "how", "does", "this", "that", "with", "from", "into", "code"}]
        score = sum(1 for t in terms if t in haystack)
        if score:
            scored.append((score, path, info))
    scored.sort(reverse=True, key=lambda x: x[0])
    selected = scored[:7] or [(0, p, i) for p, i in list(graph["files"].items())[:5]]
    evidence = []
    for score, path, info in selected:
        excerpt = info["content"][:2400]
        evidence.append({"path": path, "lines": info["lines"], "relevance": score, "excerpt": excerpt})
    context = "\n\n".join(f"FILE: {e['path']} ({e['lines']} lines)\n{e['excerpt']}" for e in evidence)
    answer, provider = await sarvam_answer(req.question, context)
    return {"answer": answer, "provider": provider, "evidence": [{"path": e["path"], "lines": e["lines"], "relevance": e["relevance"]} for e in evidence], "disclaimer": "Answers are grounded in the retrieved source excerpts. Static analysis can miss dynamic behaviour and external context."}

@app.get("/api/repos/{repo_id:path}/history")
async def get_history(repo_id: str, path: str, request: Request):
    graph = REPOS.get(repo_id)
    if not graph or path not in graph["files"]:
        raise HTTPException(404, "File not found")
    full_name = graph["metadata"].get("full_name", "")
    if "/" not in full_name:
        return {"commits": [], "note": "Commit history is available for connected GitHub repositories."}
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        response = await client.get(f"https://api.github.com/repos/{full_name}/commits", params={"path": path, "per_page": 8})
        if response.status_code == 404:
            return {"commits": [], "note": "No commit history was returned for this file."}
        if response.status_code >= 400:
            raise HTTPException(response.status_code, "Could not retrieve file history from GitHub")
        commits = []
        for item in response.json():
            commit = item.get("commit", {})
            author = commit.get("author") or {}
            commits.append({"sha": item.get("sha", "")[:8], "message": (commit.get("message") or "").splitlines()[0], "author": author.get("name", "Unknown"), "date": author.get("date", ""), "url": item.get("html_url", "")})
        return {"commits": commits, "note": "Commit messages are historical evidence, not guaranteed explanations of original intent."}

@app.post("/api/repos/{repo_id:path}/security/scan")
async def run_security_scan(repo_id: str, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")
    report = await security_report({p: info["content"] for p, info in graph["files"].items()})
    report["repository"] = graph["metadata"].get("full_name", repo_id)
    report["scanned_at"] = int(time.time())
    return report

@app.post("/api/repos/{repo_id:path}/investigate")
async def autonomous_investigate(repo_id: str, req: InvestigationRequest, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")
    terms = [t for t in re.findall(r"[a-z_][a-z0-9_]{2,}", req.question.lower()) if t not in {"what", "why", "how", "does", "could", "would", "should", "this", "that", "with", "from", "into", "code", "file"}]
    scored = []
    for path, info in graph["files"].items():
        haystack = (path + " " + info["content"]).lower()
        score = sum(3 for term in terms if term in path.lower()) + sum(1 for term in terms if term in haystack)
        if score:
            scored.append((score, path, info))
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = scored[:5] or [(0, p, i) for p, i in list(graph["files"].items())[:4]]
    evidence_paths = {p for _, p, _ in selected}
    for edge in graph["edges"]:
        if edge["type"] == "IMPORTS":
            src = edge["source"].removeprefix("file:")
            dst = edge["target"].removeprefix("file:")
            if src in evidence_paths or dst in evidence_paths:
                evidence_paths.update((src, dst))
    evidence_paths = set(list(evidence_paths)[:9])
    evidence = [{"path": p, "lines": graph["files"][p]["lines"], "excerpt": graph["files"][p]["content"][:1800]} for p in sorted(evidence_paths) if p in graph["files"]]
    graph_edges = [e for e in graph["edges"] if e["source"].removeprefix("file:") in evidence_paths or e["target"].removeprefix("file:") in evidence_paths][:35]
    context = "\n\n".join(f"FILE: {e['path']} ({e['lines']} lines)\n{e['excerpt']}" for e in evidence)
    context += "\nGRAPH RELATIONSHIPS (static-analysis evidence):\n" + json.dumps(graph_edges[:35])
    steps = [
        {"step": "Question decomposition", "detail": "Extracted technical terms and likely repository concepts from the investigation question."},
        {"step": "Evidence retrieval", "detail": f"Selected {len(evidence)} source files using lexical relevance and repository paths."},
        {"step": "Graph expansion", "detail": f"Expanded evidence across import relationships; inspected {len(graph_edges)} nearby graph edges."},
        {"step": "Evidence synthesis", "detail": "Asked the configured language model to distinguish observed code from inferred intent."}
    ]
    answer, provider = await sarvam_answer(req.question, context)
    cited = [e["path"] for e in evidence if e["path"] in answer]
    verification = {
        "status": "evidence_referenced" if cited else "needs_review",
        "cited_files": cited,
        "retrieved_files": [e["path"] for e in evidence],
        "note": "This is a traceability check, not proof that every natural-language claim is true. Review the cited source before relying on the conclusion."
    }
    record = {"id": hashlib.sha256(f"{repo_id}:{time.time_ns()}:{req.question}".encode()).hexdigest()[:16], "question": req.question, "answer": answer, "provider": provider, "evidence": evidence, "steps": steps, "verification": verification, "created_at": int(time.time())}
    user = getattr(request.state, "user", None)\n    save_investigation(repo_id, user.get("id") if user else None, record)\n    audit(user, "investigation.run", repo_id, req.question[:160])\n    INVESTIGATIONS[repo_id].insert(0, record)
    INVESTIGATIONS[repo_id] = INVESTIGATIONS[repo_id][:100]
    return record

@app.get("/api/repos/{repo_id:path}/investigations")
async def investigation_history(repo_id: str):
    if repo_id not in REPOS:
        raise HTTPException(404, "Repository not found")
    return {"items": load_investigations(repo_id)}

@app.get("/api/repos/{repo_id:path}/reports")
async def repository_report(repo_id: str):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found")
    return {
        "generated_at": int(time.time()),
        "repository": graph["metadata"],
        "statistics": graph["stats"],
        "technical_debt": debt_report(graph),
        "investigations": load_investigations(repo_id, 20),
        "limitations": ["Static analysis cannot establish runtime exploitability.", "Dependency checks cover supported exact-version manifests and the OSV database.", "Dynamic imports and external runtime configuration may be missed."]
    }

@app.post("/api/repos/{repo_id:path}/change-simulate")
async def simulate_change(repo_id: str, req: ChangeSimulationRequest, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found")
    changed = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", req.diff, re.M)))
    impacted = [impact_report(graph, path) for path in changed if path in graph["files"]]
    proposed_findings = scan_source({"proposed-change.diff": req.diff})
    context = "CHANGE DESCRIPTION:\n" + req.description + "\nPROPOSED DIFF:\n" + req.diff[:18000]
    context += "\nCURRENT REPOSITORY IMPACT:\n" + json.dumps(impacted)
    context += "\nSTATIC SECURITY PATTERN FINDINGS IN DIFF:\n" + json.dumps(proposed_findings[:30])
    answer, provider = await sarvam_answer("Review this proposed change. Explain behaviour changes, compatibility risks, affected modules, security concerns, and tests to run. Clearly label unknowns. " + req.description, context)
    audit(getattr(request.state, "user", None), "change.simulate", repo_id, f"{len(changed)} changed paths")\n    return {"description": req.description, "changed_paths": changed, "impact": impacted, "security_findings": proposed_findings, "answer": answer, "provider": provider, "disclaimer": "This is a static preflight review, not execution, formal verification, or a guarantee that the patch is safe."}

@app.post("/api/repos/{repo_id:path}/pull-request/review")
async def review_pull_request(repo_id: str, req: PullRequestReviewRequest, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Scan the base repository first.")
    match = re.match(r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/(\d+)", req.url.strip())
    if not match:
        raise HTTPException(400, "Enter a GitHub pull request URL.")
    owner, repo, number = match.groups()
    expected = graph["metadata"].get("full_name", "").lower()
    if expected and expected != f"{owner}/{repo}".lower():
        raise HTTPException(400, "The pull request must belong to the scanned repository.")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        response = await client.get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}/files", params={"per_page": 100})
        if response.status_code >= 400:
            raise HTTPException(response.status_code, "Could not retrieve pull request files. Check repository access and GitHub rate limits.")
        pr_files = response.json()
    changed = []
    diff_parts = []
    for item in pr_files[:80]:
        patch = item.get("patch") or ""
        changed.append({"path": item.get("filename"), "status": item.get("status"), "additions": item.get("additions", 0), "deletions": item.get("deletions", 0), "changes": item.get("changes", 0)})
        if patch:
            diff_parts.append(f"FILE: {item.get('filename')} | STATUS: {item.get('status')}\n{patch[:6000]}")
    diff = "\n\n".join(diff_parts)
    findings = scan_source({"pull-request.patch": diff})
    impacts = [impact_report(graph, item["path"]) for item in changed if item["path"] in graph["files"]]
    context = "PULL REQUEST FILES:\n" + json.dumps(changed) + "\nDIFF PATCHES:\n" + diff[:20000] + "\nDEPENDENCY IMPACT:\n" + json.dumps(impacts) + "\nSTATIC SECURITY PATTERNS:\n" + json.dumps(findings[:35])
    answer, provider = await sarvam_answer("Act as a cautious senior security-minded code reviewer. Review this pull request for correctness, regressions, security, dependency and test risks. Prioritise actionable findings and cite changed file paths. Do not claim tests ran.", context)
    audit(getattr(request.state, "user", None), "pull_request.review", repo_id, req.url)\n    return {"pull_request": req.url, "files": changed, "impact": impacts, "security_findings": findings, "review": answer, "provider": provider, "limitations": ["GitHub omits patch text for some large or binary files.", "Only the returned PR file patches are analysed.", "No tests are executed and no merge decision is made automatically."]}

@app.get("/api/repos/{repo_id:path}/file")
async def get_file(repo_id: str, path: str):
    graph = REPOS.get(repo_id)
    if not graph or path not in graph["files"]:
        raise HTTPException(404, "File not found")
    info = graph["files"][path]
    return {"path": path, "content": info["content"], "lines": info["lines"], "language": info["language"]}

@app.get("/")
async def index():
    return FileResponse("static/index.html")

app.mount("/static", StaticFiles(directory="static"), name="static")
