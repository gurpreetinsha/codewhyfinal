from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
import secrets
import hmac
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
from dotenv import load_dotenv
_env_file = Path(__file__).resolve().parent.parent / ".env"
if _env_file.exists():
    load_dotenv(dotenv_path=_env_file)
load_dotenv()
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.security import redact_source, security_report, scan_source
from app.auth import (
    AUTH_REQUIRED, CSRF_COOKIE, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI,
    SESSION_COOKIE, audit, audit_list, create_session, delete_session, get_session, init_auth_db,
    load_investigations, load_security_scans, oauth_ready, save_investigation, save_security_scan,
    valid_csrf, save_sentinel_investigation, load_sentinel_investigations, get_sentinel_investigation,
    update_sentinel_finding_status, get_sentinel_finding_statuses, delete_sentinel_investigation,
    list_users, get_user, update_user_role, update_user_status, disconnect_user
)
from app.sentinel import (
    SUPPORTED_LANGUAGES, build_sentinel_graph, persist_sentinel_graph,
    query_neo4j_sentinel_context, identify_security_sensitive_components,
    reconstruct_defensive_attack_paths, understand_multilingual_security_question,
    generate_evidence_backed_investigation
)
from app.shield import (
    FIREWALL_ENABLED, MAX_STANDARD_PAYLOAD_BYTES, MAX_UPLOAD_PAYLOAD_BYTES,
    init_shield_db, record_security_event, list_security_events, get_security_stats,
    create_incident, list_incidents, get_incident, update_incident,
    check_rate_limit, sanitize_input_identifier, validate_request_payload,
    get_trust_center_data, get_soc2_readiness_data
)

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None

APP_NAME = "CODEWHY"
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
SARVAM_API_KEY = os.getenv("SARVAM_API_KEY", "")
SARVAM_MODEL = os.getenv("SARVAM_MODEL", "sarvam-105b")
SARVAM_API_BASE = os.getenv("SARVAM_API_BASE", "https://api.sarvam.ai/v2").rstrip("/")
MAX_REPO_FILES = min(max(int(os.getenv("MAX_REPO_FILES", "350")), 10), 2000)
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
SECURITY_REPORTS: dict[str, dict[str, Any]] = {}
SENTINEL_GRAPHS: dict[str, dict[str, Any]] = {}
RATE_BUCKETS: dict[str, list[float]] = defaultdict(list)
OAUTH_STATE_COOKIE = "codewhy_oauth_state"
init_auth_db()
init_shield_db()
if AUTH_REQUIRED and not oauth_ready():
    raise RuntimeError("AUTH_REQUIRED=true needs GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, GITHUB_OAUTH_REDIRECT_URI, and SESSION_SECRET (32+ characters).")

DEMO_FILES = {
    "README.md": "# Atlas Commerce\nA small commerce API demo with authentication, order processing, and payment integration.\n",
    "src/orders/service.py": "from src.payments.gateway import charge\nfrom src.orders.repository import save_order\n\ndef create_order(user_id, items):\n    total = sum(item['price'] for item in items)\n    payment = charge(user_id, total)\n    return save_order(user_id, items, payment)\n",
    "src/payments/gateway.py": "def charge(user_id, amount):\n    # TODO: add idempotency key before production rollout\n    return {'user_id': user_id, 'amount': amount, 'status': 'authorized'}\n",
    "src/orders/repository.py": "def save_order(user_id, items, payment):\n    return {'id': 'ord_demo_001', 'user_id': user_id, 'items': items, 'payment': payment}\n",
    "src/notifications/email.py": "def send_order_confirmation(order):\n    return True\n",
    "src/auth/service.py": "import os\nimport hashlib\n\n# Static credential secret for developer token verification\nJWT_SECRET_KEY = 'atlas_dev_secret_key_insecure'\n\ndef authenticate_user(username, password):\n    # TODO: upgrade plain credential comparison to bcrypt\n    if username == 'admin' and password == 'secret123':\n        return {'user_id': 'usr_001', 'role': 'admin'}\n    return None\n\ndef verify_token(token):\n    if token.startswith('atlas-auth-'):\n        return {'valid': True, 'user_id': 'usr_001'}\n    return {'valid': False}\n",
    "src/api/routes.py": "from src.auth.service import authenticate_user, verify_token\nfrom src.orders.service import create_order\n\n# @app.post('/api/v1/auth/login')\ndef login_endpoint(request):\n    payload = request.get('body', {})\n    return authenticate_user(payload.get('username'), payload.get('password'))\n\n# @app.post('/api/v1/orders')\ndef create_order_endpoint(request):\n    token = request.get('headers', {}).get('Authorization', '')\n    auth = verify_token(token)\n    if not auth.get('valid'):\n        return {'error': 'unauthorized'}\n    return create_order(auth.get('user_id'), request.get('items', []))\n",
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
        if ext in {".js", ".jsx", ".ts", ".tsx"}:
            function_pattern = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)")
            for match in function_pattern.finditer(content):
                result["functions"].append({"name": match.group(1) or match.group(2), "line": content.count("\n", 0, match.start()) + 1, "end_line": content.count("\n", 0, match.start()) + 1, "args": 0})
            for match in re.finditer(r"class\s+([A-Za-z_$][\w$]*)", content):
                result["classes"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1})
            result["imports"] = re.findall(r"(?:from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\))", content)
            result["imports"] = [x[0] or x[1] for x in result["imports"]]
        elif ext == ".go":
            for match in re.finditer(r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", content):
                result["functions"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1, "end_line": content.count("\n", 0, match.start()) + 1, "args": 0})
            for match in re.finditer(r"type\s+([A-Za-z_]\w*)\s+(?:struct|interface)", content):
                result["classes"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1})
            result["imports"] = re.findall(r'^\s*"([^"]+)"\s*$', content, re.M)
        elif ext == ".rs":
            for match in re.finditer(r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\(", content):
                result["functions"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1, "end_line": content.count("\n", 0, match.start()) + 1, "args": 0})
            for match in re.finditer(r"(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_]\w*)", content):
                result["classes"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1})
            result["imports"] = re.findall(r"^\s*use\s+([^;]+);", content, re.M)
        elif ext == ".java":
            for match in re.finditer(r"(?:public|protected|private|static|final|synchronized|abstract|native|\s)+[\w<>\[\]?., ]+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws\s+[\w, ]+)?\s*\{", content):
                if match.group(1) not in {"if", "for", "while", "switch", "catch"}:
                    result["functions"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1, "end_line": content.count("\n", 0, match.start()) + 1, "args": 0})
            for match in re.finditer(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)", content):
                result["classes"].append({"name": match.group(1), "line": content.count("\n", 0, match.start()) + 1})
            result["imports"] = re.findall(r"^\s*import\s+([\w.]+);", content, re.M)
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
        fid = f"file:{repo_id}:{path}"
        nodes.append({"id": fid, "label": PurePosixPath(path).name, "type": "file", "path": path, "language": info["language"], "lines": info["lines"]})
        for fn in info["functions"]:
            nid = f"fn:{repo_id}:{path}:{fn['name']}"
            file_to_functions[path].append(nid)
            nodes.append({"id": nid, "label": fn["name"], "type": "function", "path": path, "line": fn["line"], "args": fn["args"]})
            edges.append({"source": fid, "target": nid, "type": "DEFINES", "source_path": path, "target_path": path})
        for cls in info["classes"]:
            nid = f"class:{repo_id}:{path}:{cls['name']}"
            nodes.append({"id": nid, "label": cls["name"], "type": "class", "path": path, "line": cls["line"]})
            edges.append({"source": fid, "target": nid, "type": "DEFINES", "source_path": path, "target_path": path})
    for path, info in parsed.items():
        for module in info["imports"]:
            target = _resolve_import(path, module, known)
            if target and target != path:
                edges.append({"source": f"file:{repo_id}:{path}", "target": f"file:{repo_id}:{target}", "type": "IMPORTS", "source_path": path, "target_path": target})
    # Approximate call links across known function names; marked as syntactic evidence.
    function_index = defaultdict(list)
    for path, info in parsed.items():
        for fn in info["functions"]:
            function_index[fn["name"]].append((path, fn))
    for path, info in parsed.items():
        for call in set(info["calls"]):
            for target_path, fn in function_index.get(call, []):
                if target_path != path:
                    edges.append({"source": f"file:{repo_id}:{path}", "target": f"fn:{repo_id}:{target_path}:{call}", "type": "CALLS", "source_path": path, "target_path": target_path})
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
    """Replace the repository subgraph atomically with the analyzed graph."""
    if not driver:
        return
    repo_id = graph["id"]
    files = [n for n in graph["nodes"] if n["type"] == "file"]
    symbols = [n for n in graph["nodes"] if n["type"] != "file"]
    edges = [e for e in graph["edges"] if e["type"] in {"IMPORTS", "CALLS"}]

    with driver.session(database=NEO4J_DATABASE) as session:
        def write(tx):
            tx.run(
                "MERGE (r:Repository {id:$id}) "
                "SET r.name=$name, r.scanned_at=$scanned_at, r.metadata=$metadata "
                "WITH r OPTIONAL MATCH (r)-[:CONTAINS]->(old:File) "
                "DETACH DELETE old",
                id=repo_id,
                name=graph["metadata"].get("full_name", repo_id),
                scanned_at=graph["scanned_at"],
                metadata=json.dumps(graph["metadata"]),
            )
            if files:
                tx.run(
                    "MATCH (r:Repository {id:$repo}) "
                    "UNWIND $files AS item "
                    "CREATE (f:File {id:item.id, path:item.path, label:item.label, "
                    "language:item.language, lines:item.lines}) "
                    "CREATE (r)-[:CONTAINS]->(f)",
                    repo=repo_id,
                    files=[{k: n.get(k) for k in ("id", "path", "label", "language", "lines")} for n in files],
                )
            if symbols:
                tx.run(
                    "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(f:File) "
                    "UNWIND $symbols AS item "
                    "WITH f,item WHERE f.path=item.path "
                    "FOREACH (_ IN CASE WHEN item.type='function' THEN [1] ELSE [] END | "
                    "  CREATE (n:Function {id:item.id, name:item.label, path:item.path, line:item.line, args:item.args}) "
                    "  CREATE (f)-[:DEFINES]->(n)) "
                    "FOREACH (_ IN CASE WHEN item.type='class' THEN [1] ELSE [] END | "
                    "  CREATE (n:CodeClass {id:item.id, name:item.label, path:item.path, line:item.line}) "
                    "  CREATE (f)-[:DEFINES]->(n))",
                    repo=repo_id,
                    symbols=[{k: n.get(k) for k in ("id", "path", "label", "type", "line", "args")} for n in symbols],
                )
            if edges:
                tx.run(
                    "UNWIND $edges AS item "
                    "MATCH (a {id:item.source}), (b {id:item.target}) "
                    "FOREACH (_ IN CASE WHEN item.type='IMPORTS' THEN [1] ELSE [] END | "
                    "  CREATE (a)-[:IMPORTS]->(b)) "
                    "FOREACH (_ IN CASE WHEN item.type='CALLS' THEN [1] ELSE [] END | "
                    "  CREATE (a)-[:CALLS]->(b))",
                    edges=[{"source": e["source"], "target": e["target"], "type": e["type"]} for e in edges],
                )
        session.execute_write(write)


def load_graph_from_neo4j(repo_id: str, graph_template: dict[str, Any]) -> dict[str, Any]:
    """Read persisted Neo4j nodes and relationships back for the API/UI response."""
    if not driver:
        return graph_template
    with driver.session(database=NEO4J_DATABASE) as session:
        file_rows = list(session.run(
            "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(f:File) "
            "RETURN f.id AS id, f.path AS path, f.label AS label, "
            "f.language AS language, f.lines AS lines ORDER BY f.path",
            repo=repo_id,
        ))
        symbol_rows = list(session.run(
            "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(:File)-[:DEFINES]->(s) "
            "RETURN s.id AS id, s.name AS label, s.path AS path, "
            "s.line AS line, s.args AS args, "
            "CASE WHEN s:Function THEN 'function' ELSE 'class' END AS type "
            "ORDER BY s.path, s.line, s.name",
            repo=repo_id,
        ))
        edge_rows = list(session.run(
            "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(a:File) "
            "MATCH (a)-[rel:IMPORTS|CALLS]->(b) "
            "RETURN a.id AS source, b.id AS target, type(rel) AS type, "
            "a.path AS source_path, b.path AS target_path "
            "ORDER BY source, target, type",
            repo=repo_id,
        ))
    files = [{
        "id": row["id"], "label": row["label"], "type": "file",
        "path": row["path"], "language": row["language"], "lines": row["lines"],
    } for row in file_rows]
    symbols = [{
        "id": row["id"], "label": row["label"], "type": row["type"],
        "path": row["path"], "line": row["line"], "args": row["args"],
    } for row in symbol_rows]
    edges = [{
        "source": row["source"], "target": row["target"], "type": row["type"],
        "source_path": row["source_path"], "target_path": row["target_path"],
    } for row in edge_rows]
    loaded = dict(graph_template)
    loaded["nodes"] = files + symbols
    loaded["edges"] = edges
    loaded["stats"] = {
        **graph_template["stats"],
        "files": len(files),
        "functions": sum(n["type"] == "function" for n in symbols),
        "classes": sum(n["type"] == "class" for n in symbols),
        "imports": sum(e["type"] == "IMPORTS" for e in edges),
    }
    return loaded

def numbered_excerpt(content: str, max_chars: int) -> str:
    content = redact_source(content)
    numbered = "\n".join(f"{line_no:04d}: {line}" for line_no, line in enumerate(content.splitlines(), 1))
    return numbered[:max_chars]

def graph_view(graph: dict[str, Any]) -> dict[str, Any]:
    return {"nodes": graph["nodes"], "edges": graph["edges"], "files": {p: {"lines": info["lines"], "language": info["language"]} for p, info in graph["files"].items()}, "stats": graph["stats"], "metadata": graph["metadata"], "scanned_at": graph["scanned_at"]}

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

def neo4j_graph_context(repo_id: str, paths: set[str]) -> list[dict[str, Any]]:
    if not driver or not paths:
        return []
    try:
        result = driver.execute_query(
            "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(f:File) "
            "WHERE f.path IN $paths "
            "OPTIONAL MATCH (f)-[rel:IMPORTS|CALLS|DEFINES]-(neighbor) "
            "RETURN f.path AS file, type(rel) AS relationship, labels(neighbor) AS labels, "
            "neighbor.path AS neighbor_path, neighbor.name AS neighbor_name LIMIT 100",
            repo=repo_id, paths=list(paths), database_=NEO4J_DATABASE
        )
        return [dict(record) for record in result.records if record.get("relationship")]
    except Exception as exc:
        print(f"[CODEWHY] Neo4j context query failed: {exc}")
        return []


def impact_report(graph: dict[str, Any], path: str) -> dict[str, Any]:
    if path not in graph["files"]:
        raise HTTPException(404, "File not found in scanned repository")
    if driver:
        try:
            direct_result = driver.execute_query(
                "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(target:File {path:$path}) "
                "MATCH (r)-[:CONTAINS]->(dependent:File)-[:IMPORTS]->(target) "
                "RETURN collect(DISTINCT dependent.path) AS paths",
                repo=graph["id"], path=path, database_=NEO4J_DATABASE
            )
            transitive_result = driver.execute_query(
                "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(target:File {path:$path}) "
                "MATCH (r)-[:CONTAINS]->(dependent:File)-[:IMPORTS*1..8]->(target) "
                "RETURN collect(DISTINCT dependent.path) AS paths",
                repo=graph["id"], path=path, database_=NEO4J_DATABASE
            )
            direct = sorted(direct_result.records[0]["paths"]) if direct_result.records else []
            transitive = sorted(set(transitive_result.records[0]["paths"]) - {path}) if transitive_result.records else []
            return {"path": path, "direct_dependents": direct, "transitive_dependents": transitive, "count": len(transitive), "source": "neo4j", "note": "Impact is computed from persisted Neo4j IMPORTS relationships; dynamic imports and runtime behaviour may not be represented."}
        except Exception as exc:
            print(f"[CODEWHY] Neo4j impact query failed; using in-memory graph: {exc}")
    reverse = defaultdict(set)
    for edge in graph["edges"]:
        if edge["type"] == "IMPORTS":
            reverse[edge.get("target_path", edge["target"].removeprefix("file:"))].add(edge.get("source_path", edge["source"].removeprefix("file:")))
    seen, queue = set(), [path]
    while queue:
        current = queue.pop(0)
        for parent in reverse.get(current, set()):
            if parent not in seen and parent != path:
                seen.add(parent)
                queue.append(parent)
    return {"path": path, "direct_dependents": sorted(reverse.get(path, set())), "transitive_dependents": sorted(seen), "count": len(seen), "source": "in_memory", "note": "Impact is inferred from statically detected import relationships; dynamic imports and runtime behaviour may not be represented."}

async def github_files(owner: str, repo: str, branch: str | None = None, token: str | None = None) -> tuple[dict[str, str], dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
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
        manifests = {"requirements.txt", "requirements-dev.txt", "requirements.lock", "package.json", "package-lock.json", "poetry.lock", "uv.lock", "cargo.lock", "go.sum", ".env", ".env.local", ".env.production", "application.properties", "secrets.yml", "secrets.yaml"}
        candidates = [x for x in tree if x.get("type") == "blob" and (PurePosixPath(x["path"]).suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rs", ".md", ".yaml", ".yml", ".toml", ".properties"} or PurePosixPath(x["path"]).name.lower() in manifests) and not any(part in {".git", "node_modules", "vendor", "dist", "build", ".next"} for part in x["path"].split("/"))]
        candidates.sort(key=lambda x: 0 if PurePosixPath(x["path"]).name.lower() in manifests else 1)
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

class RoleUpdateRequest(BaseModel):
    role: str

class StatusUpdateRequest(BaseModel):
    status: str

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

class SpeechSynthesisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2500)
    language_code: str = Field(default="en-IN", max_length=12)

class SentinelInvestigateRequest(BaseModel):
    repo_id: str
    question: str = Field(min_length=2, max_length=2000)
    language_code: str = Field(default="en-IN", max_length=12)
    original_transcript: str = Field(default="", max_length=2500)
    speak_response: bool = Field(default=False)

class FindingStatusUpdateRequest(BaseModel):
    repo_id: str
    status: str = Field(default="open")
    notes: str = Field(default="", max_length=500)

class UnderstandQueryRequest(BaseModel):
    question: str = Field(min_length=2, max_length=2000)
    language_code: str = Field(default="en-IN", max_length=12)

class IncidentUpdateRequest(BaseModel):
    status: str | None = None
    resolution_notes: str | None = None
    assigned_to: str | None = None

class IncidentCreateRequest(BaseModel):
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=10, max_length=2000)
    severity: str = Field(default="medium")
    endpoint: str = Field(default="")

class VulnerabilityReportRequest(BaseModel):
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=10, max_length=2000)
    reporter_contact: str = Field(default="", max_length=200)
    severity: str = Field(default="medium")
    affected_component: str = Field(default="")

@app.middleware("http")
async def auth_and_tenant_middleware(request: Request, call_next):
    raw_path = request.url.path
    client_ip = request.client.host if request.client else "unknown"

    # 1. Request Method Validation
    if request.method in {"TRACE", "TRACK", "CONNECT"}:
        record_security_event(
            event_type="waf.blocked",
            severity="medium",
            ip_address=client_ip,
            endpoint=raw_path,
            method=request.method,
            result="blocked",
            detail=f"Disallowed HTTP method '{request.method}' rejected by Application Firewall.",
        )
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": f"Method {request.method} is not allowed."}, status_code=405)

    # 2. Path & Query Sanitation (Anti-traversal & null-byte injection)
    query_str = str(request.url.query)
    if "/.." in raw_path or "..\\" in raw_path or "\x00" in raw_path or "%00" in query_str or "\x00" in query_str:
        record_security_event(
            event_type="waf.blocked",
            severity="high",
            ip_address=client_ip,
            endpoint=raw_path,
            method=request.method,
            result="blocked",
            detail="Path traversal or null-byte pattern detected in request URI.",
        )
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Malformed request path or invalid characters detected."}, status_code=400)

    # 3. Request Size & Content-Type Limits
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            cl = int(content_length)
            is_upload = any(x in raw_path for x in ("/voice/", "/scan", "/upload"))
            max_limit = MAX_UPLOAD_PAYLOAD_BYTES if is_upload else MAX_STANDARD_PAYLOAD_BYTES
            if cl > max_limit:
                record_security_event(
                    event_type="waf.blocked",
                    severity="medium",
                    ip_address=client_ip,
                    endpoint=raw_path,
                    method=request.method,
                    result="blocked",
                    detail=f"Request size {cl} bytes exceeded firewall limit of {max_limit} bytes.",
                )
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    {"detail": f"Payload too large. Maximum allowed size is {max_limit // (1024 * 1024)} MB."},
                    status_code=413,
                )
        except ValueError:
            pass

    if request.method in {"POST", "PUT", "PATCH"} and raw_path.startswith("/api/"):
        ct = request.headers.get("content-type", "").lower()
        if ct and not any(ct.startswith(x) for x in ("application/json", "multipart/form-data", "application/x-www-form-urlencoded")):
            record_security_event(
                event_type="waf.blocked",
                severity="low",
                ip_address=client_ip,
                endpoint=raw_path,
                method=request.method,
                result="blocked",
                detail=f"Unsupported Content-Type '{ct}' rejected.",
            )
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": f"Unsupported media type '{ct}'. Use application/json or multipart/form-data."}, status_code=415)

    # 4. Sliding-Window Rate Limiting (Serverless & persistent SQLite backing)
    if raw_path.startswith("/api/") and raw_path not in {"/api/health", "/api/auth/status"}:
        expensive = any(x in raw_path for x in ("/scan", "/investigate", "/change-simulate", "/pull-request/review", "/voice/", "/sentinel/investigate"))
        is_auth = raw_path.startswith("/api/auth/") and raw_path not in {"/api/auth/status"}
        limit = 10 if expensive else (15 if is_auth else 120)
        tier_name = "expensive" if expensive else ("auth" if is_auth else "general")
        rate_key = f"{client_ip}:{tier_name}"

        allowed, current_count, retry_after = check_rate_limit(rate_key, limit, window_seconds=60)
        if not allowed:
            record_security_event(
                event_type="ratelimit.exceeded",
                severity="medium",
                ip_address=client_ip,
                endpoint=raw_path,
                method=request.method,
                result="blocked",
                detail=f"Rate limit exceeded: {current_count}/{limit} req/min on {tier_name} tier.",
                metadata={"limit": limit, "count": current_count, "retry_after": retry_after},
            )
            from fastapi.responses import JSONResponse
            return JSONResponse(
                {"detail": f"Rate limit exceeded for {tier_name} operations. Please wait {retry_after}s before retrying."},
                status_code=429,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

    sid = request.cookies.get(SESSION_COOKIE, "")
    user = get_session(sid) if sid else None
    anon_id = request.cookies.get("codewhy_anon", "") or secrets.token_urlsafe(18)
    request.state.user = user
    request.state.anonymous_id = anon_id
    public_paths = {
        "/api/health", "/api/auth/status", "/api/auth/github", "/api/auth/callback",
        "/api/auth/logout", "/api/trust-center", "/api/trust-center/soc2", "/api/trust-center/report-vulnerability"
    }

    if AUTH_REQUIRED and raw_path.startswith("/api/") and raw_path not in public_paths and not user:
        record_security_event(
            event_type="access.unauthorized",
            severity="low",
            ip_address=client_ip,
            endpoint=raw_path,
            method=request.method,
            result="blocked",
            detail="Unauthenticated API request rejected under AUTH_REQUIRED=true.",
        )
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Sign in with GitHub to access this workspace."}, status_code=401)

    if user and user.get("status") == "suspended" and raw_path not in {"/api/auth/status", "/api/auth/logout"}:
        record_security_event(
            event_type="access.forbidden",
            severity="medium",
            user=user,
            ip_address=client_ip,
            endpoint=raw_path,
            method=request.method,
            result="blocked",
            detail="Suspended account attempt to access protected resource.",
        )
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Your account has been suspended by an administrator."}, status_code=403)

    if user and request.method in {"POST", "PUT", "PATCH", "DELETE"} and raw_path not in {"/api/auth/logout", "/api/trust-center/report-vulnerability"}:
        csrf = request.headers.get("X-CSRF-Token", "")
        if not valid_csrf(user, csrf):
            record_security_event(
                event_type="access.forbidden",
                severity="medium",
                user=user,
                ip_address=client_ip,
                endpoint=raw_path,
                method=request.method,
                result="blocked",
                detail="CSRF token validation failure on state-changing request.",
            )
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "CSRF validation failed. Refresh and try again."}, status_code=403)

    for repo_id, owner in REPO_OWNERS.items():
        if raw_path == "/api/repos/" + repo_id or raw_path.startswith("/api/repos/" + repo_id + "/"):
            if owner.startswith("anon:"):
                if user or owner != "anon:" + anon_id:
                    from fastapi.responses import JSONResponse
                    return JSONResponse({"detail": "Repository access denied."}, status_code=404)
            elif owner != "anonymous":
                if not user:
                    from fastapi.responses import JSONResponse
                    return JSONResponse({"detail": "Sign in to access this repository workspace."}, status_code=401)
                if owner.lower() != user["login"].lower():
                    from fastapi.responses import JSONResponse
                    return JSONResponse({"detail": "Repository access denied."}, status_code=404)

    response = await call_next(request)
    if not user and not request.cookies.get("codewhy_anon"):
        response.set_cookie("codewhy_anon", anon_id, httponly=True, secure=request.url.scheme == "https", samesite="lax", max_age=60 * 60 * 24 * 30, path="/")

    # 5. Security Headers Injection
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(self), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://avatars.githubusercontent.com; "
        "media-src 'self' blob: data:; "
        "connect-src 'self' https://api.github.com https://api.sarvam.ai; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self' https://github.com;"
    )
    return response


@app.get("/api/auth/status")
async def auth_status(request: Request):
    user = getattr(request.state, "user", None)
    return {
        "auth_required": AUTH_REQUIRED,
        "oauth_configured": oauth_ready(),
        "authenticated": bool(user),
        "user": ({
            "id": user["id"],
            "login": user["login"],
            "name": user.get("name") or user["login"],
            "avatar_url": user.get("avatar_url", ""),
            "role": user.get("role", "developer"),
            "status": user.get("status", "active"),
            "has_token": user.get("has_token", True)
        } if user else None),
        "csrf_token": request.cookies.get(CSRF_COOKIE, "")
    }

@app.get("/api/auth/github")
async def github_oauth_start():
    if not oauth_ready():
        raise HTTPException(503, "GitHub OAuth is not configured. Set the OAuth environment variables first.")
    state = secrets.token_urlsafe(32)
    from urllib.parse import urlencode
    params = urlencode({"client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI, "scope": "read:user user:email repo", "state": state})
    response = RedirectResponse("https://github.com/login/oauth/authorize?" + params, status_code=302)
    response.set_cookie(
        OAUTH_STATE_COOKIE, state, httponly=True,
        secure=OAUTH_REDIRECT_URI.startswith("https://"),
        samesite="lax", max_age=600, path="/api/auth",
    )
    return response

@app.get("/api/auth/callback")
async def github_oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None
):
    from urllib.parse import quote
    # 1. Handle user cancellation or error returned by GitHub
    if error:
        err_msg = error_description or error or "GitHub authentication was cancelled."
        response = RedirectResponse(f"/?auth_error={quote(err_msg)}", status_code=302)
        response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
        audit(None, "auth.cancelled", "", err_msg)
        return response

    if not code or not state:
        response = RedirectResponse("/?auth_error=Missing%20authorization%20code%20or%20state.", status_code=302)
        response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
        return response

    expected_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
    if not expected_state or not hmac.compare_digest(expected_state, state):
        response = RedirectResponse("/?auth_error=OAuth%20state%20expired%20or%20invalid.%20Please%20try%20again.", status_code=302)
        response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
        return response

    async with httpx.AsyncClient(timeout=20) as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            json={
                "client_id": OAUTH_CLIENT_ID,
                "client_secret": OAUTH_CLIENT_SECRET,
                "code": code,
                "redirect_uri": OAUTH_REDIRECT_URI
            }
        )
        if token_response.status_code >= 400:
            response = RedirectResponse("/?auth_error=GitHub%20token%20exchange%20failed.", status_code=302)
            response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
            return response
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            err = token_data.get("error_description") or "GitHub did not issue an access token."
            response = RedirectResponse(f"/?auth_error={quote(err)}", status_code=302)
            response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
            return response

        profile_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"}
        )
        if profile_response.status_code >= 400:
            response = RedirectResponse("/?auth_error=Could%20not%20retrieve%20GitHub%20profile.", status_code=302)
            response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
            return response
        profile = profile_response.json()

    sid, csrf = create_session(profile, access_token)
    user = {"id": profile["id"], "login": profile["login"]}
    audit(user, "auth.login", "", "GitHub OAuth")
    response = RedirectResponse("/?auth_success=1", status_code=302)
    secure = OAUTH_REDIRECT_URI.startswith("https://")
    response.set_cookie(SESSION_COOKIE, sid, httponly=True, secure=secure, samesite="lax", max_age=43200, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="lax", max_age=43200, path="/")
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
    return response

@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    user = getattr(request.state, "user", None)
    delete_session(request.cookies.get(SESSION_COOKIE, ""))
    audit(user, "auth.logout")
    from fastapi.responses import JSONResponse
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response

@app.get("/api/github/repos")
async def github_repositories(request: Request, page: int = 1, per_page: int = 100):
    """List repositories visible to the signed-in GitHub account."""
    user = getattr(request.state, "user", None)
    if not user or not user.get("access_token"):
        raise HTTPException(401, "Sign in with GitHub to list your repositories.")
    page = max(1, min(page, 100))
    per_page = max(1, min(per_page, 100))
    headers = {
        "Authorization": f"Bearer {user['access_token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        response = await client.get(
            "https://api.github.com/user/repos",
            params={"visibility": "all", "affiliation": "owner,collaborator,organization_member",
                    "sort": "updated", "per_page": per_page, "page": page},
        )
    if response.status_code == 401:
        raise HTTPException(401, "GitHub access expired. Sign in again.")
    if response.status_code == 403:
        raise HTTPException(403, "GitHub denied repository listing. Check OAuth repository permissions or organisation approval.")
    if response.status_code >= 400:
        raise HTTPException(response.status_code, "Could not list GitHub repositories.")
    repos = response.json()
    return {"repositories": [{
        "id": item["id"], "full_name": item["full_name"], "name": item["name"],
        "description": item.get("description"), "private": item.get("private", False),
        "default_branch": item.get("default_branch", "main"), "language": item.get("language"),
        "stargazers_count": item.get("stargazers_count", 0),
        "html_url": item.get("html_url"), "updated_at": item.get("updated_at"),
        "permissions": {"push": bool((item.get("permissions") or {}).get("push")),
                        "admin": bool((item.get("permissions") or {}).get("admin"))},
    } for item in repos], "page": page, "per_page": per_page}

@app.post("/api/auth/disconnect")
async def auth_disconnect(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in first.")
    disconnect_user(user["id"])
    audit(user, "auth.disconnect", "", "GitHub account disconnected")
    from fastapi.responses import JSONResponse
    response = JSONResponse({"status": "disconnected"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response

@app.get("/api/auth/repositories")
async def user_repositories(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in with GitHub to view your authorized repositories.")
    if user.get("status") == "suspended":
        raise HTTPException(403, "Account suspended.")
    token = user.get("access_token")
    if not token:
        raise HTTPException(400, "No active GitHub connection. Reconnect your GitHub account.")

    async with httpx.AsyncClient(timeout=20) as client:
        res = await client.get(
            "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        )
        if res.status_code == 401:
            disconnect_user(user["id"])
            raise HTTPException(401, "GitHub authorization expired or was revoked. Please sign in again.")
        if res.status_code >= 400:
            raise HTTPException(502, f"Failed to fetch repositories from GitHub ({res.status_code}).")
        raw_repos = res.json()

    repos = []
    for r in raw_repos:
        repos.append({
            "id": r["id"],
            "full_name": r["full_name"],
            "name": r["name"],
            "owner": r["owner"]["login"] if isinstance(r.get("owner"), dict) else "",
            "private": bool(r.get("private")),
            "html_url": r.get("html_url", ""),
            "default_branch": r.get("default_branch", "main"),
            "description": r.get("description") or ""
        })
    return {"repositories": repos}

@app.get("/api/admin/users")
async def get_admin_users(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    return {"users": list_users()}

@app.patch("/api/admin/users/{github_id}/role")
async def change_user_role(github_id: int, req: RoleUpdateRequest, request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    if user["id"] == github_id and req.role.lower() != "admin":
        raise HTTPException(400, "Administrators cannot demote themselves to prevent lockout.")
    try:
        updated = update_user_role(github_id, req.role, admin_user=user)
        return {"status": "ok", "user": updated}
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))

@app.patch("/api/admin/users/{github_id}/status")
async def change_user_status(github_id: int, req: StatusUpdateRequest, request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    if user["id"] == github_id and req.status.lower() == "suspended":
        raise HTTPException(400, "Administrators cannot suspend their own account.")
    try:
        updated = update_user_status(github_id, req.status, admin_user=user)
        return {"status": "ok", "user": updated}
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))

@app.get("/api/admin/audit")
async def get_audit(request: Request, limit: int = 100):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    return {"events": audit_list(limit)}

# --- CODEWHY SECURITY SHIELD & TRUST CENTER ENDPOINTS ---

@app.get("/api/trust-center")
async def trust_center_endpoint():
    """Public Trust Center API disclosing verified controls, architecture, and data privacy."""
    return get_trust_center_data()


@app.get("/api/trust-center/soc2")
async def soc2_readiness_endpoint():
    """Public SOC 2 Readiness documentation, policies, and controls evidence register."""
    return get_soc2_readiness_data()


@app.post("/api/trust-center/report-vulnerability")
async def report_vulnerability_endpoint(req: VulnerabilityReportRequest, request: Request):
    """Responsible vulnerability disclosure reporting endpoint."""
    client_ip = request.client.host if request.client else "unknown"
    evidence = {
        "reporter_contact": req.reporter_contact,
        "affected_component": req.affected_component,
        "ip_address": client_ip,
        "reported_at": int(time.time()),
    }
    incident = create_incident(
        title=f"External Disclosure: {req.title}",
        description=req.description,
        severity=req.severity,
        endpoint=req.affected_component or "/trust-center/report",
        actor=req.reporter_contact or f"External ({client_ip})",
        evidence=evidence,
        assigned_to="Product Security Team",
    )
    record_security_event(
        event_type="vulnerability.reported",
        severity=req.severity,
        ip_address=client_ip,
        endpoint="/api/trust-center/report-vulnerability",
        method="POST",
        result="flagged",
        detail=f"External disclosure: {req.title}",
        metadata={"incident_id": incident["id"], "reporter": req.reporter_contact},
    )
    return {
        "status": "received",
        "incident_id": incident["id"],
        "message": f"Thank you for responsibly reporting. Your report has been catalogued under incident ID {incident['id']} with our Product Security Team. We review all submissions within our 24-hour SLA.",
    }


@app.get("/api/admin/security/stats")
async def admin_security_stats(request: Request):
    """Security Shield metrics, event totals, rate-limit blocks, and incident counts."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    return get_security_stats()


@app.get("/api/admin/security/events")
async def admin_security_events(
    request: Request,
    event_type: str | None = None,
    severity: str | None = None,
    login: str | None = None,
    repo_id: str | None = None,
    result: str | None = None,
    limit: int = 100,
):
    """Filtered security event logs for administrators."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    events = list_security_events(
        limit=limit,
        event_type=event_type,
        severity=severity,
        login=login,
        repo_id=repo_id,
        result=result,
    )
    return {"events": events, "count": len(events)}


@app.get("/api/admin/security/incidents")
async def admin_security_incidents(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
):
    """List security incidents with filtering by status and severity."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    incidents = list_incidents(status=status, severity=severity, limit=limit)
    return {"incidents": incidents, "count": len(incidents)}


@app.post("/api/admin/security/incidents")
async def admin_create_incident(req: IncidentCreateRequest, request: Request):
    """Manually file a security incident from the admin dashboard."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    incident = create_incident(
        title=req.title,
        description=req.description,
        severity=req.severity,
        endpoint=req.endpoint,
        actor=user["login"],
        assigned_to="Security Incident Team",
    )
    record_security_event(
        event_type="incident.created",
        severity="medium",
        user=user,
        endpoint=req.endpoint,
        detail=f"Manual incident {incident['id']} opened: {req.title}",
        metadata={"incident_id": incident["id"]},
    )
    return {"status": "ok", "incident": incident}


@app.patch("/api/admin/security/incidents/{incident_id}")
async def admin_update_incident(incident_id: str, req: IncidentUpdateRequest, request: Request):
    """Update incident status (new, investigating, contained, resolved, closed) and resolution notes."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in required.")
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator role required.")
    try:
        updated = update_incident(
            incident_id=incident_id,
            status=req.status,
            resolution_notes=req.resolution_notes,
            assigned_to=req.assigned_to,
            admin_user=user,
        )
        return {"status": "ok", "incident": updated}
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@app.get("/api/health")
async def health():
    return {"status": "ok", "sarvam_configured": bool(SARVAM_API_KEY), "neo4j_connected": bool(driver), "auth_required": AUTH_REQUIRED, "oauth_configured": oauth_ready()}

@app.get("/api/demo")
async def demo(request: Request):
    user = getattr(request.state, "user", None)
    demo_id = f"{user['login']}::demo/atlas-commerce" if user else f"anon:{request.state.anonymous_id}::demo/atlas-commerce"
    graph = build_graph(demo_id, DEMO_FILES, {"full_name": "atlas-commerce/demo", "description": "A sample commerce backend with orders, payments, and a legacy pricing module.", "default_branch": "main", "html_url": "https://github.com", "demo": True})
    REPOS[graph["id"]] = graph
    REPO_OWNERS[graph["id"]] = user["login"] if user else "anon:" + request.state.anonymous_id
    return {"repository": graph_view(graph), "debt": debt_report(graph), "id": graph["id"]}

@app.post("/api/repos/scan")
async def scan(req: ScanRequest, request: Request):
    match = re.match(r"^(?:https?://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", req.url.strip())
    if not match:
        raise HTTPException(400, "Enter a GitHub repository URL like https://github.com/owner/repo")
    owner, repo = match.groups()
    user = getattr(request.state, "user", None)
    files, meta = await github_files(owner, repo, req.branch, user.get("access_token") if user else None)
    repo_key = f"{user['login']}::{owner}/{repo}" if user else f"anon:{request.state.anonymous_id}::{owner}/{repo}"
    graph = build_graph(repo_key, files, meta)
    REPOS[graph["id"]] = graph
    REPO_OWNERS[graph["id"]] = user["login"] if user else "anonymous"
    audit(user, "repository.scan", graph["id"], f"Loaded {len(files)} files")
    storage = "memory"
    if driver:
        try:
            persist_graph(graph)
            graph = load_graph_from_neo4j(graph["id"], graph)
            REPOS[graph["id"]] = graph
            storage = "neo4j"
        except Exception as exc:
            print(f"[CODEWHY] Graph persistence/readback failed: {exc}")
            raise HTTPException(503, "Neo4j graph persistence failed; no in-memory substitute was returned.")
    return {"repository": graph_view(graph), "debt": debt_report(graph), "id": graph["id"], "storage": storage}

@app.get("/api/repos")
async def repos(request: Request):
    user = getattr(request.state, "user", None)
    visible = [g for g in REPOS.values() if REPO_OWNERS.get(g["id"]) == ("anon:" + request.state.anonymous_id) or (user and REPO_OWNERS.get(g["id"]) == user["login"])]
    return [{"id": g["id"], "metadata": g["metadata"], "stats": g["stats"]} for g in visible]

@app.get("/api/repos/{repo_id:path}/graph")
async def get_graph(repo_id: str):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository has not been scanned in this app session")
    if driver:
        try:
            graph = load_graph_from_neo4j(repo_id, graph)
            REPOS[repo_id] = graph
        except Exception as exc:
            print(f"[CODEWHY] Neo4j graph read failed: {exc}")
            raise HTTPException(503, "Could not read the repository graph from Neo4j.")
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



class CodeHelperAnalyzeRequest(BaseModel):
    repo_id: str = Field(min_length=1, max_length=300)
    path: str = Field(min_length=1, max_length=500)
    focus: str = Field(default="Find correctness bugs, edge cases, security issues and maintainability improvements.", max_length=1500)


class CodeHelperCommitRequest(BaseModel):
    repo_id: str = Field(min_length=1, max_length=300)
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=180000)
    message: str = Field(min_length=5, max_length=200)
    branch: str | None = Field(default=None, max_length=200)


def _sentinel_repo_for_user(repo_id: str, request: Request) -> dict[str, Any]:
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")
    user = getattr(request.state, "user", None)
    owner = REPO_OWNERS.get(repo_id)
    if owner and owner.startswith("anon:"):
        if user or owner != "anon:" + getattr(request.state, "anonymous_id", ""):
            raise HTTPException(403, "Repository access denied.")
    elif owner and owner != "anonymous":
        if not user or owner.lower() != user["login"].lower():
            raise HTTPException(403, "Repository access denied.")
    return graph


@app.post("/api/sentinel/code-helper/analyze")
async def sentinel_code_helper_analyze(req: CodeHelperAnalyzeRequest, request: Request):
    """Review one scanned source file and propose a complete safer replacement."""
    graph = _sentinel_repo_for_user(req.repo_id, request)
    info = graph["files"].get(req.path)
    if not info:
        raise HTTPException(404, "File not found in the scanned repository.")
    source = info["content"]
    if len(source) > 45000:
        raise HTTPException(413, "This file is too large for one review. Choose a smaller file.")
    redacted = redact_source(source)
    static_signals = []
    if PurePosixPath(req.path).suffix.lower() == ".py":
        try:
            ast.parse(source)
        except SyntaxError as exc:
            static_signals.append({
                "severity": "high", "category": "syntax",
                "line": exc.lineno, "title": "Python syntax error",
                "detail": exc.msg
            })
    for finding in scan_source({req.path: source})[:25]:
        static_signals.append({
            "severity": finding.get("severity", "medium"),
            "category": finding.get("category", "static"),
            "line": finding.get("line"),
            "title": finding.get("title", "Static analysis signal"),
            "detail": finding.get("recommendation") or finding.get("evidence") or ""
        })
    prompt = """You are CODEWHY SENTINEL CODE HELPER, a senior software engineer and careful code reviewer.
Review only the supplied file and repository metadata. Identify real bugs, incorrect logic, edge cases, security issues and meaningful maintainability improvements. Do not invent issues. Clearly distinguish definite bugs from suggestions.
Return exactly these sections:
## Summary
## Issues
For each issue include severity (critical/high/medium/low), line number (or unknown), why it is a problem, and a concrete consequence.
## Improved Code
Provide one complete replacement file inside a single fenced code block using the correct language. Preserve existing behaviour unless changing it fixes a clearly explained bug. Do not use placeholders or omit unrelated sections.
## Tests to Run
List specific tests or checks. Never claim they were executed.
If no worthwhile issues exist, say so and still provide the unchanged file as the replacement.
Do not include secrets or reproduce redacted values."""
    context = (
        f"FILE PATH: {req.path}\nFOCUS: {req.focus}\n"
        f"LANGUAGE: {info.get('language', 'unknown')}\n"
        f"STATIC CHECK SIGNALS: {json.dumps(static_signals)}\n"
        f"FILE CONTENT (sensitive values redacted):\n{redacted[:45000]}"
    )
    review, provider = await sarvam_answer(
        f"Review this source file and return issues plus a complete improved replacement. Focus: {req.focus}",
        context,
        system_prompt=prompt
    )
    replacement_match = re.search(r"```(?:[A-Za-z0-9_+.-]+)?\s*\n([\s\S]*?)\n```", review)
    replacement = replacement_match.group(1) if replacement_match else ""
    if not replacement:
        raise HTTPException(502, "The code reviewer did not return a complete fenced replacement file. Try again with a smaller file.")
    # Reject accidental truncation/placeholder output rather than offering it as a ready-to-commit fix.
    if re.search(r"(?im)^\s*(\.\.\.|#\s*rest of (the )?code|//\s*rest of (the )?code|TODO:\s*implement)", replacement):
        raise HTTPException(502, "The proposed replacement appears incomplete. Narrow the review focus and retry.")
    audit(getattr(request.state, "user", None), "sentinel.code_helper.analyze", req.repo_id, req.path)
    return {
        "repo_id": req.repo_id, "path": req.path, "language": info.get("language", "text"),
        "review": review, "replacement": replacement, "static_signals": static_signals,
        "provider": provider,
        "original_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "disclaimer": "AI-generated changes are suggestions. Review the diff and run your tests before committing."
    }


@app.post("/api/sentinel/code-helper/commit")
async def sentinel_code_helper_commit(req: CodeHelperCommitRequest, request: Request):
    """Commit a user-approved reviewed replacement to a new GitHub branch."""
    graph = _sentinel_repo_for_user(req.repo_id, request)
    user = getattr(request.state, "user", None)
    if not user or not user.get("access_token"):
        raise HTTPException(401, "Sign in with GitHub to commit changes.")
    if REPO_OWNERS.get(req.repo_id, "").lower() != user["login"].lower():
        raise HTTPException(403, "Only the authenticated owner of this scanned workspace can commit.")
    if graph.get("metadata", {}).get("demo"):
        raise HTTPException(400, "Demo repositories cannot be committed.")
    full_name = graph.get("metadata", {}).get("full_name", "")
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", full_name)
    if not match:
        raise HTTPException(400, "The scanned repository metadata is invalid.")
    owner, repo = match.groups()
    path = req.path.strip("/")
    if not path or any(part in {"", ".", ".."} for part in path.split("/")) or "\\" in path or "\x00" in path:
        raise HTTPException(400, "Invalid repository file path.")
    current = graph["files"].get(path)
    if not current:
        raise HTTPException(404, "The selected file is not part of the scanned snapshot.")
    default_branch = graph["metadata"].get("default_branch") or "main"
    branch = req.branch or f"codewhy/fix-{int(time.time())}"
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch) or branch.startswith("/") or branch.endswith("/") or ".." in branch:
        raise HTTPException(400, "Invalid branch name.")
    headers = {
        "Authorization": f"Bearer {user['access_token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    async with httpx.AsyncClient(timeout=35, headers=headers) as client:
        meta_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        if meta_resp.status_code >= 400:
            raise HTTPException(meta_resp.status_code, "Could not verify repository access with GitHub.")
        meta = meta_resp.json()
        if meta.get("full_name", "").lower() != full_name.lower():
            raise HTTPException(409, "Repository identity changed since the scan.")
        # Check that the file has not changed since it was scanned.
        file_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            params={"ref": default_branch}
        )
        if file_resp.status_code >= 400:
            raise HTTPException(file_resp.status_code, "Could not verify the current file on the default branch.")
        file_data = file_resp.json()
        if file_data.get("type") != "file":
            raise HTTPException(400, "The selected path is not a regular file.")
        import base64
        try:
            live_content = base64.b64decode(file_data.get("content", "")).decode("utf-8")
        except Exception:
            raise HTTPException(422, "GitHub could not provide this file as UTF-8 text.")
        if hashlib.sha256(live_content.encode()).hexdigest() != hashlib.sha256(current["content"].encode()).hexdigest():
            raise HTTPException(409, "This file changed on GitHub after the scan. Rescan the repository before committing.")
        # Create an isolated branch from the current default branch.
        ref_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{default_branch}")
        if ref_resp.status_code >= 400:
            raise HTTPException(ref_resp.status_code, "Could not read the current default branch.")
        base_sha = ref_resp.json()["object"]["sha"]
        create_branch = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": base_sha}
        )
        if create_branch.status_code >= 400:
            if create_branch.status_code == 422:
                raise HTTPException(409, "That fix branch already exists. Choose another branch name.")
            raise HTTPException(create_branch.status_code, "Could not create the fix branch.")
        # Commit the proposed replacement on the new branch only.
        encoded = base64.b64encode(req.content.encode()).decode()
        update_resp = await client.put(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            json={
                "message": req.message,
                "content": encoded,
                "branch": branch,
                "sha": file_data["sha"]
            }
        )
        if update_resp.status_code >= 400:
            raise HTTPException(update_resp.status_code, "GitHub created the fix branch but could not commit the file. The default branch is unchanged.")
        commit_sha = update_resp.json().get("commit", {}).get("sha")
        commit_url = update_resp.json().get("commit", {}).get("html_url")
    audit(user, "sentinel.code_helper.commit", req.repo_id, f"{path} -> {branch}")
    return {
        "success": True, "branch": branch, "commit_sha": commit_sha,
        "commit_url": commit_url, "path": path,
        "pull_request_url": f"https://github.com/{owner}/{repo}/compare/{default_branch}...{branch}?expand=1"
    }

async def sarvam_answer(question: str, context: str, system_prompt: str | None = None) -> tuple[str, str]:
    if not SARVAM_API_KEY:
        return ("Sarvam AI is not configured yet. Add SARVAM_API_KEY to your deployment environment to enable live answers. The repository evidence is ready and shown alongside this response.", "not_configured")
    question = redact_source(question)
    context = redact_source(context)
    system = system_prompt or """You are CODEWHY, a careful staff-level software architect. Answer only from the supplied repository evidence. Clearly distinguish direct evidence from inference. Never invent business intent, runtime behaviour, commit history, tests, or ownership. If the evidence is insufficient, say what is unknown and what additional evidence would establish it. Cite file paths and line numbers where available. Be concise but useful."""
    async with httpx.AsyncClient(timeout=75) as client:
        try:
            response = await client.post(
                f"{SARVAM_API_BASE}/chat/completions",
                headers={"api-subscription-key": SARVAM_API_KEY, "Content-Type": "application/json"},
                json={
                    "model": SARVAM_MODEL,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": f"QUESTION:\n{question}\n\nREPOSITORY EVIDENCE:\n{context}"}
                    ],
                    "temperature": 0.25,
                    "reasoning_effort": "low",
                    "max_tokens": 3000
                }
            )
            response.raise_for_status()
            data = response.json()
            message = data["choices"][0]["message"]
            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                return "Sarvam returned no user-facing answer for this request. Try a narrower question or reduce the amount of retrieved context.", "sarvam_empty_response"
            return content.strip(), "sarvam"
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
    terms = [t for t in re.findall(r"[a-z_]{3,}", q) if t not in {"what", "why", "how", "does", "this", "that", "with", "from", "into", "code"}]
    scored = []
    for path, info in graph["files"].items():
        haystack = (path + " " + info["content"]).lower()
        score = sum(1 for t in terms if t in haystack)
        if score:
            scored.append((score, path, info))
    scored.sort(reverse=True, key=lambda x: x[0])
    selected = scored[:7] or [(0, p, i) for p, i in list(graph["files"].items())[:5]]
    evidence = []
    for score, path, info in selected:
        excerpt = numbered_excerpt(info["content"], 2400)
        evidence.append({"path": path, "lines": info["lines"], "relevance": score, "excerpt": excerpt})
    context = "\n\n".join(f"FILE: {e['path']} ({e['lines']} lines)\n{e['excerpt']}" for e in evidence)
    related_edges = [edge for edge in graph["edges"] if edge.get("source_path") in {e["path"] for e in evidence} or edge.get("target_path") in {e["path"] for e in evidence}]
    context += "\nIN-MEMORY GRAPH RELATIONSHIPS:\n" + json.dumps(related_edges[:35])
    persisted_context = neo4j_graph_context(repo_id, {e["path"] for e in evidence})
    if persisted_context:
        context += "\nNEO4J GRAPH NEIGHBOURHOOD:\n" + json.dumps(persisted_context)
    security_terms = {"security", "vulnerability", "vulnerabilities", "vulnerable", "secret", "secrets", "attack", "attacks", "injection", "injections", "token", "tokens", "credential", "credentials", "exploit", "exploits", "password", "passwords"}
    if security_terms.intersection(set(terms)):
        security_data = SECURITY_REPORTS.get(repo_id)
        if not security_data:
            security_data = await security_report({p: info["content"] for p, info in graph["files"].items()})
            security_data["attack_paths"] = attack_path_report(graph, security_data["findings"])
            SECURITY_REPORTS[repo_id] = security_data
        context += "\nRELATED SECURITY FINDINGS:\n" + json.dumps([item for item in security_data["findings"] if item.get("path") in {e["path"] for e in evidence} or item.get("category") == "dependency"][:25])
        context += "\nPOTENTIAL ATTACK PATH CANDIDATES:\n" + json.dumps([item for item in security_data.get("attack_paths", []) if item.get("source_file") in {e["path"] for e in evidence} or item.get("sink_file") in {e["path"] for e in evidence}][:10])
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
    user = getattr(request.state, "user", None)
    token = user.get("access_token") if user else None
    if token:
        headers["Authorization"] = f"Bearer {token}"
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

def attack_path_report(graph: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    source_patterns = [re.compile(r"@(?:app|router)\.(?:get|post|put|patch|delete)\s*\("), re.compile(r"\bapp\.route\s*\("), re.compile(r"\b(?:req\.body|request\.json|request\.form|request\.query_params)\b")]
    sink_patterns = [re.compile(r"\b(?:eval|exec)\s*\("), re.compile(r"subprocess\.(?:run|Popen|call)\s*\("), re.compile(r"\bpickle\.loads?\s*\("), re.compile(r"\byaml\.load\s*\("), re.compile(r"\.execute\s*\(")]
    sources, sinks = set(), set()
    for path, info in graph["files"].items():
        content = info["content"]
        if any(pattern.search(content) for pattern in source_patterns):
            sources.add(path)
        if any(pattern.search(content) for pattern in sink_patterns):
            sinks.add(path)
    adjacency = defaultdict(set)
    for edge in graph["edges"]:
        if edge["type"] == "IMPORTS":
            adjacency[edge.get("source_path", edge["source"].removeprefix("file:"))].add(edge.get("target_path", edge["target"].removeprefix("file:")) )
    paths = []
    for source in sorted(sources):
        queue = [(source, [source])]
        visited = {source}
        while queue:
            current, chain = queue.pop(0)
            if current in sinks and current != source:
                paths.append({"source_file": source, "sink_file": current, "path": chain, "classification": "potential_static_route", "evidence": "A route/input-like source and a risky sink are connected by import edges. This does not prove data flow or exploitability."})
                break
            for nxt in sorted(adjacency.get(current, set())):
                if nxt not in visited and len(chain) < 7:
                    visited.add(nxt)
                    queue.append((nxt, chain + [nxt]))
        if len(paths) >= 20:
            break
    return paths

@app.post("/api/voice/transcribe")
async def voice_transcribe(
    file: UploadFile = File(...),
    mode: str = Form("codemix"),
    language_code: str = Form(None)
):
    if not SARVAM_API_KEY:
        raise HTTPException(503, "Add SARVAM_API_KEY to enable Sarvam speech recognition.")
    allowed_modes = {"transcribe", "translate", "verbatim", "translit", "codemix"}
    if mode not in allowed_modes:
        raise HTTPException(400, "Unsupported transcription mode.")
    audio = await file.read(15 * 1024 * 1024 + 1)
    if not audio or len(audio) > 15 * 1024 * 1024:
        raise HTTPException(413, "Audio must be non-empty and no larger than 15 MB.")

    # Normalize MIME type: Sarvam API strictly allows only specific types without parameter suffixes like ;codecs=opus
    raw_content_type = (file.content_type or "audio/webm").split(";")[0].strip().lower()
    allowed_types = {
        "audio/mpeg", "audio/mp3", "audio/mpeg3", "audio/x-mpeg-3", "audio/x-mp3",
        "audio/wav", "audio/x-wav", "audio/wave", "audio/pcm_s16le", "audio/l16",
        "audio/raw", "application/octet-stream", "audio/aac", "audio/x-aac",
        "audio/aiff", "audio/x-aiff", "audio/ogg", "audio/opus", "audio/flac",
        "audio/x-flac", "audio/mp4", "audio/x-m4a", "audio/amr", "audio/x-ms-wma",
        "audio/webm", "video/webm"
    }
    content_type = raw_content_type if raw_content_type in allowed_types else "audio/webm"
    filename = file.filename or "recording.webm"
    if not filename.endswith((".webm", ".wav", ".mp3", ".ogg", ".flac", ".m4a", ".aac")):
        filename = f"{filename}.webm"

    data_payload: dict[str, Any] = {"model": "saaras:v4", "mode": mode}
    if language_code and language_code != "unknown":
        data_payload["language_code"] = language_code

    try:
        async with httpx.AsyncClient(timeout=45) as client:
            response = await client.post(
                "https://api.sarvam.ai/speech-to-text",
                headers={"api-subscription-key": SARVAM_API_KEY},
                data=data_payload,
                files={"file": (filename, audio, content_type)},
            )
            response.raise_for_status()
            data = response.json()
            return {
                "transcript": data.get("transcript", ""),
                "language_code": data.get("language_code", ""),
                "request_id": data.get("request_id"),
                "model": "saaras:v4",
                "mode": mode,
                "duration_limit_seconds": 30
            }
    except httpx.HTTPStatusError as exc:
        err_msg = f"Sarvam speech recognition returned {exc.response.status_code}."
        try:
            err_json = exc.response.json()
            if isinstance(err_json, dict) and "error" in err_json:
                detail = err_json["error"].get("message")
                if detail:
                    err_msg = f"Sarvam AI: {detail}"
        except Exception:
            pass
        raise HTTPException(502, err_msg)
    except (httpx.RequestError, ValueError) as exc:
        raise HTTPException(502, f"Speech recognition failed: {exc}")

@app.post("/api/voice/speak")
async def voice_speak(req: SpeechSynthesisRequest):
    if not SARVAM_API_KEY:
        raise HTTPException(503, "Add SARVAM_API_KEY to enable Sarvam speech synthesis.")
    async with httpx.AsyncClient(timeout=45) as client:
        try:
            response = await client.post(
                "https://api.sarvam.ai/text-to-speech",
                headers={"api-subscription-key": SARVAM_API_KEY, "Content-Type": "application/json"},
                json={"text": req.text, "language_code": req.language_code, "model": "bulbul:v4-flash", "speaker": "shubh_enhi_ads", "enable_preprocessing": True},
            )
            response.raise_for_status()
            data = response.json()
            if not data.get("audios"):
                raise HTTPException(502, "Sarvam returned no audio data.")
            return {"audio_base64": data["audios"][0], "mime_type": "audio/wav", "language_code": req.language_code, "model": "bulbul:v4-flash"}
        except httpx.HTTPStatusError as exc:
            raise HTTPException(502, f"Sarvam speech synthesis returned {exc.response.status_code}.")
        except httpx.RequestError as exc:
            raise HTTPException(502, f"Speech synthesis failed: {exc}")

@app.post("/api/repos/{repo_id:path}/security/scan")
async def run_security_scan(repo_id: str, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")
    report = await security_report({p: info["content"] for p, info in graph["files"].items()})
    report["repository"] = graph["metadata"].get("full_name", repo_id)
    report["attack_paths"] = attack_path_report(graph, report["findings"])
    report["scanned_at"] = int(time.time())
    user = getattr(request.state, "user", None)
    report["timeline_delta"] = save_security_scan(repo_id, user.get("id") if user else None, report)
    SECURITY_REPORTS[repo_id] = report
    audit(user, "security.scan", repo_id, f"{report['summary']['total']} findings")
    return report

async def github_history_context(graph: dict[str, Any], paths: set[str], token: str | None = None) -> list[dict[str, str]]:
    full_name = graph["metadata"].get("full_name", "")
    if graph["metadata"].get("demo") or "/" not in full_name:
        return []
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    history = []
    async with httpx.AsyncClient(timeout=18, headers=headers) as client:
        for path in sorted(paths)[:3]:
            try:
                response = await client.get(f"https://api.github.com/repos/{full_name}/commits", params={"path": path, "per_page": 3})
                if response.status_code >= 400:
                    continue
                for item in response.json()[:3]:
                    commit = item.get("commit", {})
                    author = commit.get("author") or {}
                    history.append({"path": path, "sha": item.get("sha", "")[:8], "date": author.get("date", ""), "message": (commit.get("message") or "").splitlines()[0]})
            except (httpx.RequestError, ValueError, KeyError):
                continue
    return history


@app.get("/api/repos/{repo_id:path}/security-history")
async def security_history(repo_id: str):
    if repo_id not in REPOS:
        raise HTTPException(404, "Scan this repository first.")
    return {"items": load_security_scans(repo_id, 30)}


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
            src = edge.get("source_path", edge["source"].removeprefix("file:"))
            dst = edge.get("target_path", edge["target"].removeprefix("file:"))
            if src in evidence_paths or dst in evidence_paths:
                evidence_paths.update((src, dst))
    evidence_paths = set(sorted(evidence_paths)[:9])
    evidence = [{"path": p, "lines": graph["files"][p]["lines"], "excerpt": numbered_excerpt(graph["files"][p]["content"], 1800)} for p in sorted(evidence_paths) if p in graph["files"]]
    graph_edges = [e for e in graph["edges"] if e.get("source_path") in evidence_paths or e.get("target_path") in evidence_paths][:35]
    context = "\n\n".join(f"FILE: {e['path']} ({e['lines']} lines)\n{e['excerpt']}" for e in evidence)
    context += "\nIN-MEMORY GRAPH RELATIONSHIPS (static-analysis evidence):\n" + json.dumps(graph_edges[:35])
    persisted_context = neo4j_graph_context(repo_id, evidence_paths)
    if persisted_context:
        context += "\nNEO4J GRAPH NEIGHBOURHOOD (persisted relationships):\n" + json.dumps(persisted_context)
    user = getattr(request.state, "user", None)
    history_context = await github_history_context(graph, evidence_paths, user.get("access_token") if user else None)
    if history_context:
        context += "\nGITHUB COMMIT HISTORY (historical clues, not proof of intent):\n" + json.dumps(history_context)
    security_context = []
    security_terms = {"security", "vulnerability", "vulnerabilities", "vulnerable", "secret", "secrets", "attack", "attacks", "injection", "injections", "token", "tokens", "credential", "credentials", "exploit", "exploits", "password", "passwords"}
    if security_terms.intersection(set(terms)):
        security_report_data = SECURITY_REPORTS.get(repo_id)
        if not security_report_data:
            security_report_data = await security_report({p: info["content"] for p, info in graph["files"].items()})
            security_report_data["attack_paths"] = attack_path_report(graph, security_report_data["findings"])
            SECURITY_REPORTS[repo_id] = security_report_data
        security_context = [item for item in security_report_data["findings"] if item.get("path") in evidence_paths or item.get("category") == "dependency"][:30]
        if security_context:
            context += "\nRELATED SECURITY FINDINGS (static/advisory evidence):\n" + json.dumps(security_context)
            context += "\nPOTENTIAL ATTACK PATH CANDIDATES:\n" + json.dumps([item for item in security_report_data.get("attack_paths", []) if item.get("source_file") in evidence_paths or item.get("sink_file") in evidence_paths][:10])
    steps = [
        {"step": "Question decomposition", "detail": "Extracted technical terms and likely repository concepts from the investigation question."},
        {"step": "Evidence retrieval", "detail": f"Selected {len(evidence)} source files using lexical relevance and repository paths."},
        {"step": "Graph expansion", "detail": f"Expanded evidence across import relationships; inspected {len(graph_edges)} nearby graph edges."},
        {"step": "Historical and security correlation", "detail": f"Retrieved {len(history_context)} recent commit messages and {len(security_context)} related security findings where relevant."},
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
    record = {"id": hashlib.sha256(f"{repo_id}:{time.time_ns()}:{req.question}".encode()).hexdigest()[:16], "question": redact_source(req.question), "answer": answer, "provider": provider, "evidence": evidence, "steps": steps, "verification": verification, "created_at": int(time.time())}
    user = getattr(request.state, "user", None)
    save_investigation(repo_id, user.get("id") if user else None, record)
    audit(user, "investigation.run", repo_id, redact_source(req.question)[:160])
    INVESTIGATIONS[repo_id].insert(0, record)
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
        "security": SECURITY_REPORTS.get(repo_id),
        "security_history": load_security_scans(repo_id, 20),
        "limitations": ["Static analysis cannot establish runtime exploitability.", "Dependency checks cover supported exact-version manifests and the OSV database.", "Dynamic imports and external runtime configuration may be missed."]
    }

@app.post("/api/repos/{repo_id:path}/change-simulate")
async def simulate_change(repo_id: str, req: ChangeSimulationRequest, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found")
    changed = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", req.diff, re.M)))
    impacted = [impact_report(graph, path) for path in changed if path in graph["files"]]
    diff_files = {}
    for match in re.finditer(r"(?ms)^diff --git a/(.+?) b/(.+?)\n(.*?)(?=^diff --git|\Z)", req.diff):
        diff_files[match.group(2)] = match.group(3)
    proposed_findings = scan_source(diff_files or {"proposed-change.diff": req.diff})
    context = "CHANGE DESCRIPTION:\n" + req.description + "\nPROPOSED DIFF:\n" + req.diff[:18000]
    context += "\nCURRENT REPOSITORY IMPACT:\n" + json.dumps(impacted)
    context += "\nSTATIC SECURITY PATTERN FINDINGS IN DIFF:\n" + json.dumps(proposed_findings[:30])
    answer, provider = await sarvam_answer("Review this proposed change. Explain behaviour changes, compatibility risks, affected modules, security concerns, and tests to run. Clearly label unknowns. " + req.description, context)
    audit(getattr(request.state, "user", None), "change.simulate", repo_id, f"{len(changed)} changed paths")
    return {"description": req.description, "changed_paths": changed, "impact": impacted, "security_findings": proposed_findings, "answer": answer, "provider": provider, "disclaimer": "This is a static preflight review, not execution, formal verification, or a guarantee that the patch is safe."}

@app.post("/api/repos/{repo_id:path}/pull-request/review")
async def review_pull_request(repo_id: str, req: PullRequestReviewRequest, request: Request):
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Scan the base repository first.")
    user = getattr(request.state, "user", None)
    if user and user.get("role") not in {"reviewer", "admin"}:
        raise HTTPException(403, "Reviewer or administrator role required for PR review.")
    if AUTH_REQUIRED and not user:
        raise HTTPException(401, "Sign in to review pull requests.")
    match = re.match(r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/(\d+)", req.url.strip())
    if not match:
        raise HTTPException(400, "Enter a GitHub pull request URL.")
    owner, repo, number = match.groups()
    expected = graph["metadata"].get("full_name", "").lower()
    if expected and expected != f"{owner}/{repo}".lower():
        raise HTTPException(400, "The pull request must belong to the scanned repository.")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    user = getattr(request.state, "user", None)
    token = user.get("access_token") if user else None
    if token:
        headers["Authorization"] = f"Bearer {token}"
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
    patch_files = {item.get("filename", "unknown.patch"): item.get("patch", "") for item in pr_files if item.get("patch")}
    findings = scan_source(patch_files or {"pull-request.patch": diff})
    impacts = [impact_report(graph, item["path"]) for item in changed if item["path"] in graph["files"]]
    context = "PULL REQUEST FILES:\n" + json.dumps(changed) + "\nDIFF PATCHES:\n" + diff[:20000] + "\nDEPENDENCY IMPACT:\n" + json.dumps(impacts) + "\nSTATIC SECURITY PATTERNS:\n" + json.dumps(findings[:35])
    answer, provider = await sarvam_answer("Act as a cautious senior security-minded code reviewer. Review this pull request for correctness, regressions, security, dependency and test risks. Prioritise actionable findings and cite changed file paths. Do not claim tests ran.", context)
    audit(getattr(request.state, "user", None), "pull_request.review", repo_id, req.url)
    return {"pull_request": req.url, "files": changed, "impact": impacts, "security_findings": findings, "review": answer, "provider": provider, "limitations": ["GitHub omits patch text for some large or binary files.", "Only the returned PR file patches are analysed.", "No tests are executed and no merge decision is made automatically."]}

@app.get("/api/repos/{repo_id:path}/file")
async def get_file(repo_id: str, path: str):
    graph = REPOS.get(repo_id)
    if not graph or path not in graph["files"]:
        raise HTTPException(404, "File not found")
    info = graph["files"][path]
    return {"path": path, "content": info["content"], "lines": info["lines"], "language": info["language"]}

async def ensure_sentinel_graph(repo_id: str) -> dict[str, Any]:
    """Retrieve or build the complete Sentinel Knowledge Graph for a repository."""
    if repo_id in SENTINEL_GRAPHS:
        return SENTINEL_GRAPHS[repo_id]
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")
    security_data = SECURITY_REPORTS.get(repo_id)
    if not security_data:
        security_data = await security_report({p: info["content"] for p, info in graph["files"].items()})
        security_data["attack_paths"] = attack_path_report(graph, security_data["findings"])
        SECURITY_REPORTS[repo_id] = security_data
    sentinel_graph = build_sentinel_graph(
        repo_id,
        {p: info["content"] for p, info in graph["files"].items()},
        graph,
        security_data
    )
    SENTINEL_GRAPHS[repo_id] = sentinel_graph
    if driver:
        try:
            persist_sentinel_graph(driver, NEO4J_DATABASE, sentinel_graph)
        except Exception as exc:
            print(f"[CODEWHY SENTINEL] Neo4j graph persistence warning: {exc}")
    return sentinel_graph


async def generate_sarvam_speech(text: str, language_code: str = "en-IN") -> tuple[str, str]:
    """Generate audio via Sarvam Bulbul v4-flash with Indian language voice mapping."""
    if not SARVAM_API_KEY:
        return "", "unconfigured"
    voice = next((l["voice"] for l in SUPPORTED_LANGUAGES if l["code"] == language_code), "shubh_enhi_ads")
    try:
        async with httpx.AsyncClient(timeout=40) as client:
            resp = await client.post(
                "https://api.sarvam.ai/text-to-speech",
                headers={"api-subscription-key": SARVAM_API_KEY, "Content-Type": "application/json"},
                json={
                    "text": text[:2000],
                    "language_code": language_code,
                    "model": "bulbul:v4-flash",
                    "speaker": voice,
                    "enable_preprocessing": True
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                audios = data.get("audios", [])
                if audios:
                    return audios[0], "bulbul:v4-flash"
    except Exception as exc:
        print(f"[CODEWHY SENTINEL] Sarvam speech error: {exc}")
    return "", "failed"


@app.get("/api/sentinel/languages")
async def sentinel_languages():
    """Return available languages supported by Sarvam models for Sentinel voice and comprehension."""
    return {"languages": SUPPORTED_LANGUAGES}


@app.get("/api/sentinel/repos")
async def sentinel_repos(request: Request):
    """Return repositories authorized for the current user session."""
    user = getattr(request.state, "user", None)
    anon_id = "anon:" + getattr(request.state, "anonymous_id", "")
    visible = []
    for g in REPOS.values():
        owner = REPO_OWNERS.get(g["id"])
        if owner == anon_id or (user and owner == user["login"]) or owner == "anonymous":
            visible.append({
                "id": g["id"],
                "name": g["metadata"].get("full_name") or g["id"],
                "demo": bool(g["metadata"].get("demo")),
                "stats": g.get("stats", {})
            })
    return {"repositories": visible}


@app.post("/api/sentinel/understand-query")
async def sentinel_understand_query(req: UnderstandQueryRequest):
    """Parse multilingual security questions while preserving exact technical identifiers."""
    return await understand_multilingual_security_question(
        req.question,
        language_code=req.language_code,
        sarvam_api_key=SARVAM_API_KEY,
        sarvam_api_base=SARVAM_API_BASE,
        sarvam_model=SARVAM_MODEL
    )


@app.post("/api/sentinel/investigate")
async def sentinel_investigate(req: SentinelInvestigateRequest, request: Request):
    """
    Execute full end-to-end CODEWHY SENTINEL investigation:
    Voice/Text -> Question Understanding -> Neo4j Graph Retrieval -> Security Analysis -> Evidence-Backed Report -> Spoken Audio.
    """
    graph = REPOS.get(req.repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found. Scan it first.")

    # Access control verification
    user = getattr(request.state, "user", None)
    owner = REPO_OWNERS.get(req.repo_id)
    if owner:
        if owner.startswith("anon:"):
            if user or owner != "anon:" + getattr(request.state, "anonymous_id", ""):
                raise HTTPException(403, "Repository access denied.")
        elif owner != "anonymous":
            if not user or owner.lower() != user["login"].lower():
                raise HTTPException(403, "Repository access denied.")

    stages = []
    t_start = time.time()

    # Stage 1: Understanding the question
    stage1_start = time.time()
    understanding = await understand_multilingual_security_question(
        req.question,
        language_code=req.language_code,
        sarvam_api_key=SARVAM_API_KEY,
        sarvam_api_base=SARVAM_API_BASE,
        sarvam_model=SARVAM_MODEL
    )
    stages.append({
        "stage": "question_understanding",
        "title": "Understanding the question",
        "detail": f"Interpreted intent as '{understanding['detected_intent']}' while preserving {len(understanding['preserved_entities']['files'])} file(s) and {len(understanding['preserved_entities']['technical_terms'])} technical identifier(s).",
        "duration_ms": int((time.time() - stage1_start) * 1000)
    })

    # Stage 2: Processing voice input
    if req.original_transcript:
        stages.append({
            "stage": "voice_processing",
            "title": "Processing voice input",
            "detail": f"Recognized voice transcript ({req.language_code}): \"{req.original_transcript[:120]}\"",
            "duration_ms": 15
        })

    # Stage 3: Retrieving repository context
    stage3_start = time.time()
    terms = [t.lower() for t in understanding.get("search_terms", []) if len(t) >= 2]
    preserved_files = set(understanding.get("preserved_entities", {}).get("files", []))
    scored = []
    for path, info in graph["files"].items():
        haystack = (path + " " + info["content"]).lower()
        score = sum(5 for term in terms if term in path.lower()) + sum(1 for term in terms if term in haystack)
        if path in preserved_files:
            score += 25
        if score > 0:
            scored.append((score, path, info))
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = scored[:6] or [(0, p, i) for p, i in list(graph["files"].items())[:4]]

    evidence_files = []
    for _, path, info in selected:
        evidence_files.append({
            "path": path,
            "lines": info["lines"],
            "language": info["language"],
            "excerpt": numbered_excerpt(info["content"], 2200)
        })
    stages.append({
        "stage": "repository_context",
        "title": "Retrieving repository context",
        "detail": f"Retrieved {len(evidence_files)} source file excerpt(s) matching security-sensitive terms ({', '.join(terms[:5]) or 'all files'}).",
        "duration_ms": int((time.time() - stage3_start) * 1000)
    })

    # Stage 4: Exploring Neo4j relationships
    stage4_start = time.time()
    sentinel_graph = await ensure_sentinel_graph(req.repo_id)
    evidence_paths = {e["path"] for e in evidence_files}
    neo4j_records = []
    if driver:
        neo4j_records = query_neo4j_sentinel_context(driver, NEO4J_DATABASE, req.repo_id, evidence_paths, terms)
    stages.append({
        "stage": "graph_exploration",
        "title": "Exploring Neo4j relationships",
        "detail": f"Traversed knowledge graph ({'Neo4j' if driver else 'in-memory topology'}): explored {len(neo4j_records) or len(sentinel_graph.get('edges', []))} node & relationship connections.",
        "duration_ms": int((time.time() - stage4_start) * 1000)
    })

    # Stage 5: Analysing security concerns
    stage5_start = time.time()
    sensitive_components = identify_security_sensitive_components(
        {p: info["content"] for p, info in graph["files"].items()},
        sentinel_graph
    )
    security_data = SECURITY_REPORTS.get(req.repo_id, {})
    all_findings = list(security_data.get("findings", []))

    # Apply current remediation statuses
    statuses = get_sentinel_finding_statuses(req.repo_id)
    for f in all_findings:
        fid = f.get("id", "")
        f["status"] = statuses.get(fid, "open")

    attack_paths = reconstruct_defensive_attack_paths(
        sentinel_graph,
        {p: info["content"] for p, info in graph["files"].items()},
        all_findings
    )
    stages.append({
        "stage": "security_analysis",
        "title": "Analysing security concerns",
        "detail": f"Evaluated {len(sensitive_components)} security-sensitive component(s), {len(all_findings)} finding(s), and reconstructed {len(attack_paths)} defensive attack path(s).",
        "duration_ms": int((time.time() - stage5_start) * 1000)
    })

    # Stage 6: Generating evidence-backed results
    stage6_start = time.time()
    investigation_result = generate_evidence_backed_investigation(
        repo_id=req.repo_id,
        repo_meta=graph["metadata"],
        query_understanding=understanding,
        sensitive_components=sensitive_components,
        attack_paths=attack_paths,
        security_findings=all_findings,
        neo4j_context=neo4j_records,
        evidence_files=evidence_files
    )

    ai_explanation = ""
    ai_provider = "sentinel_deterministic_engine"
    if SARVAM_API_KEY:
        findings_bullets = []
        for f in investigation_result['investigated_findings'][:5]:
            findings_bullets.append(
                f"- Issue: {f['title']} in file '{f['affected_file']}' (line {f['line_number'] or 'N/A'})\n"
                f"  Supporting Evidence: {f['supporting_evidence']}\n"
                f"  Potential Impact: {f['potential_impact']}\n"
                f"  Remediation Action: {f['recommended_action']}"
            )
        findings_text = "\n".join(findings_bullets) or "No critical static vulnerabilities confirmed in this scope."

        paths_bullets = []
        for p in attack_paths[:3]:
            paths_bullets.append(
                f"- Route entrypoint '{p['entry_point']}' reaches sink '{p['sink_component']}' ({p['verification']} attack path)"
            )
        paths_text = "\n".join(paths_bullets) or "No direct attack paths detected."

        ai_context = (
            f"Codebase: {graph['metadata'].get('full_name', req.repo_id)}\n"
            f"Developer Query: {req.question}\n"
            f"Normalized Inquiry: {understanding['normalized_english_inquiry']}\n\n"
            f"CONFIRMED FINDINGS IN CODE:\n{findings_text}\n\n"
            f"ATTACK PATH CONNECTIONS:\n{paths_text}\n\n"
            f"RELEVANT CODE EXCERPTS:\n" + "\n\n".join(f"--- File: {e['path']} ---\n{e['excerpt']}" for e in evidence_files[:3])
        )

        sentinel_system = (
            "You are CODEWHY SENTINEL, a friendly, encouraging, and highly skilled cybersecurity mentor for developers. "
            "Your mission is to make security crystal clear, friendly, and simple to understand for any programmer.\n"
            "Guidelines:\n"
            "1. Speak in plain, conversational language. Avoid robotic, overly dense academic or formal jargon.\n"
            "2. Never print raw JSON, AST tokens, or internal regex patterns.\n"
            "3. If the user asked in Hindi, Hinglish, Tamil, Telugu, or another language, explain in that language naturally.\n"
            "4. Organize your explanation into 4 friendly, well-structured sections:\n"
            "   ### 🛡️ The Bottom Line\n"
            "   Give a 1-2 sentence direct answer: is the code safe or vulnerable, and what is the primary risk?\n\n"
            "   ### 🔍 What We Found (Plain Explanation)\n"
            "   Explain the flaw clearly: what component receives untrusted input, how does it flow, and where is it handled unsafely?\n\n"
            "   ### ⚠️ Real-World Impact\n"
            "   Explain what could actually happen if someone exploits this (e.g. bypass login, steal database records, access secrets).\n\n"
            "   ### 🛠️ How to Fix It (Simple Steps & Code)\n"
            "   Give plain-English instructions and a clean, safe code snippet demonstrating the fix."
        )

        try:
            ai_explanation, ai_provider = await sarvam_answer(
                f"Please explain the security findings and how to fix them in simple, clear developer-friendly words for: {understanding['normalized_english_inquiry']}",
                ai_context,
                system_prompt=sentinel_system
            )
        except Exception as exc:
            print(f"[CODEWHY SENTINEL] Sarvam explanation fallback: {exc}")

    stages.append({
        "stage": "result_generation",
        "title": "Generating evidence-backed results",
        "detail": f"Synthesized findings backed by repository evidence ({ai_provider}).",
        "duration_ms": int((time.time() - stage6_start) * 1000)
    })

    # Stage 7: Preparing spoken response (if requested)
    audio_base64 = ""
    if req.speak_response:
        stage7_start = time.time()
        spoken_text = ai_explanation or investigation_result["report_markdown"]
        clean_spoken = re.sub(r"[#*`_\-]", "", spoken_text)
        clean_spoken = " ".join(clean_spoken.split()[:80])
        audio_base64, _ = await generate_sarvam_speech(clean_spoken, req.language_code)
        stages.append({
            "stage": "audio_response",
            "title": "Preparing spoken response",
            "detail": f"Generated audio in {req.language_code} via Sarvam Bulbul." if audio_base64 else "Spoken response generation skipped or unavailable.",
            "duration_ms": int((time.time() - stage7_start) * 1000)
        })

    investigation_id = hashlib.sha256(f"{req.repo_id}:{time.time_ns()}:{req.question}".encode()).hexdigest()[:16]
    record = {
        "id": investigation_id,
        "repo_id": req.repo_id,
        "question": req.question,
        "original_transcript": req.original_transcript,
        "language_code": req.language_code,
        "interpreted_query": understanding["normalized_english_inquiry"],
        "stages": stages,
        "understanding": understanding,
        "findings": investigation_result["investigated_findings"],
        "attack_paths": attack_paths[:8],
        "sensitive_components": sensitive_components[:8],
        "sentinel_graph": {
            "nodes": sentinel_graph.get("nodes", [])[:64],
            "edges": sentinel_graph.get("edges", [])[:120],
            "stats": sentinel_graph.get("stats", {})
        },
        "graph_entities": {
            "total_nodes": len(sentinel_graph.get("nodes", [])),
            "total_edges": len(sentinel_graph.get("edges", [])),
            "apis": sentinel_graph.get("stats", {}).get("apis", 0),
            "dependencies": sentinel_graph.get("stats", {}).get("dependencies", 0),
        },
        "evidence": evidence_files,
        "report_markdown": investigation_result["report_markdown"],
        "ai_explanation": ai_explanation,
        "ai_provider": ai_provider,
        "remediation": [
            {"finding_id": f["finding_id"], "title": f["title"], "action": f["recommended_action"], "status": f["status"]}
            for f in investigation_result["investigated_findings"]
        ],
        "audio_base64": audio_base64,
        "traceability": investigation_result["traceability"],
        "created_at": int(time.time()),
        "total_duration_ms": int((time.time() - t_start) * 1000)
    }

    user_id = user.get("id") if user else None
    save_sentinel_investigation(record, user_id=user_id)
    audit(user, "sentinel.investigate", req.repo_id, f"Question: {req.question[:100]} ({req.language_code})")

    return record


@app.get("/api/sentinel/history")
async def sentinel_history(request: Request, repo_id: str | None = None, limit: int = 50):
    """Retrieve saved Sentinel investigations with repository filtering."""
    user = getattr(request.state, "user", None)
    user_id = user.get("id") if user else None
    return {"items": load_sentinel_investigations(repo_id=repo_id, limit=limit, user_id=user_id)}


@app.get("/api/sentinel/investigation/{investigation_id}")
async def sentinel_get_investigation(investigation_id: str):
    """Reopen a specific saved Sentinel investigation."""
    rec = get_sentinel_investigation(investigation_id)
    if not rec:
        raise HTTPException(404, "Investigation not found")
    return rec


@app.patch("/api/sentinel/finding/{finding_id}/status")
async def sentinel_update_finding(finding_id: str, req: FindingStatusUpdateRequest, request: Request):
    """Update a finding's remediation status (open, under_review, fixed, verified)."""
    user = getattr(request.state, "user", None)
    audit(user, "sentinel.status_update", req.repo_id, f"Finding {finding_id} -> {req.status}")
    return update_sentinel_finding_status(req.repo_id, finding_id, req.status, req.notes)


@app.post("/api/sentinel/speak")
async def sentinel_speak_response(req: SpeechSynthesisRequest):
    """Generate audio via Sarvam Text-to-Speech for an investigation response."""
    if not SARVAM_API_KEY:
        raise HTTPException(503, "Sarvam API key is not configured for speech synthesis.")
    audio_base64, provider = await generate_sarvam_speech(req.text, req.language_code)
    if not audio_base64:
        raise HTTPException(502, "Speech synthesis generation failed. Check audio format or rate limits.")
    return {"audio_base64": audio_base64, "mime_type": "audio/wav", "language_code": req.language_code, "provider": provider}


@app.get("/api/sentinel/overview/{repo_id:path}")
async def sentinel_overview(repo_id: str):
    """Return security posture, sensitive components, and attack paths for the given repository."""
    graph = REPOS.get(repo_id)
    if not graph:
        raise HTTPException(404, "Repository not found")
    sentinel_graph = await ensure_sentinel_graph(repo_id)
    sensitive_components = identify_security_sensitive_components(
        {p: info["content"] for p, info in graph["files"].items()},
        sentinel_graph
    )
    security_data = SECURITY_REPORTS.get(repo_id, {})
    findings = list(security_data.get("findings", []))
    statuses = get_sentinel_finding_statuses(repo_id)
    for f in findings:
        f["status"] = statuses.get(f.get("id"), "open")
    attack_paths = reconstruct_defensive_attack_paths(
        sentinel_graph,
        {p: info["content"] for p, info in graph["files"].items()},
        findings
    )
    return {
        "repo_id": repo_id,
        "metadata": graph["metadata"],
        "sensitive_components": sensitive_components,
        "findings": findings[:50],
        "attack_paths": attack_paths,
        "graph_stats": sentinel_graph.get("stats", {})
    }


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
