import json
import sqlite3
import pytest
from fastapi.testclient import TestClient

from app import auth
from app.main import app, ensure_sentinel_graph
from app.sentinel import (
    SUPPORTED_LANGUAGES,
    build_sentinel_graph,
    extract_apis,
    extract_technical_decisions,
    generate_evidence_backed_investigation,
    identify_security_sensitive_components,
    reconstruct_defensive_attack_paths,
    understand_multilingual_security_question,
)


def test_api_and_decision_extraction():
    files = {
        "api.py": (
            "from service import execute_task\n"
            "@app.post('/api/v1/tasks')\n"
            "def handle_tasks(request):\n"
            "    # TODO: sanitize task payload\n"
            "    return execute_task(request)\n"
        ),
        "service.py": "def execute_task(req):\n    return True\n"
    }
    apis = extract_apis(files)
    assert len(apis) == 1
    assert apis[0]["method"] == "POST"
    assert apis[0]["endpoint"] == "/api/v1/tasks"
    assert apis[0]["handler"] == "handle_tasks"

    decisions = extract_technical_decisions(files)
    assert len(decisions) == 1
    assert decisions[0]["marker"] == "TODO"
    assert "sanitize task payload" in decisions[0]["detail"]


def test_sentinel_graph_construction_and_node_types():
    files = {
        "routes.py": (
            "@app.get('/health')\n"
            "def health_check():\n"
            "    return {'status': 'ok'}\n"
        ),
        "requirements.txt": "fastapi==0.115.0\n",
    }
    base_graph = {
        "id": "test::repo",
        "files": {"routes.py": {"lines": 3, "language": "python", "functions": [{"name": "health_check", "line": 2, "args": 0}], "classes": [], "imports": [], "calls": [], "todo": 0}},
        "nodes": [{"id": "file:test::repo:routes.py", "type": "file", "path": "routes.py", "label": "routes.py"}],
        "edges": [],
        "stats": {"files": 1},
        "metadata": {"full_name": "test/repo"},
    }
    security_data = {
        "dependency_inventory": [{"name": "fastapi", "version": "0.115.0", "ecosystem": "PyPI", "manifest": "requirements.txt"}],
        "findings": [{
            "id": "find-001",
            "title": "Hard-coded key",
            "category": "secret",
            "severity": "critical",
            "path": "routes.py",
            "line": 1,
            "evidence": "key=123",
            "recommendation": "Use secret manager"
        }]
    }

    sentinel_graph = build_sentinel_graph("test::repo", files, base_graph, security_data)
    node_types = {n["type"] for n in sentinel_graph["nodes"]}
    edge_types = {e["type"] for e in sentinel_graph["edges"]}

    assert "api" in node_types
    assert "dependency" in node_types
    assert "security_finding" in node_types
    assert "DEFINES" in edge_types
    assert "DEPENDS_ON" in edge_types
    assert "CONTAINS" in edge_types


def test_security_sensitive_components_and_attack_path_reconstruction():
    files = {
        "routes.py": (
            "from auth import verify\n"
            "@app.post('/api/login')\n"
            "def login_handler(request):\n"
            "    token = request.get('token')\n"
            "    return verify(token)\n"
        ),
        "auth.py": (
            "import pickle\n"
            "def verify(token):\n"
            "    # Risky sink\n"
            "    return pickle.loads(token)\n"
        )
    }
    sentinel_graph = {
        "nodes": [
            {"id": "api:test:routes.py:POST:/api/login", "type": "api", "path": "routes.py", "label": "POST /api/login"},
            {"id": "fn:test:routes.py:login_handler", "type": "function", "path": "routes.py", "label": "login_handler"},
            {"id": "fn:test:auth.py:verify", "type": "function", "path": "auth.py", "label": "verify"},
            {"id": "file:test:auth.py", "type": "file", "path": "auth.py", "label": "auth.py"},
        ],
        "edges": [
            {"source": "api:test:routes.py:POST:/api/login", "target": "fn:test:routes.py:login_handler", "type": "CALLS"},
            {"source": "fn:test:routes.py:login_handler", "target": "fn:test:auth.py:verify", "type": "CALLS"},
            {"source": "fn:test:auth.py:verify", "target": "file:test:auth.py", "type": "DEFINES"},
        ],
        "files": {
            "routes.py": {"lines": 5},
            "auth.py": {"lines": 5},
        }
    }
    findings = [{
        "id": "find-pickle",
        "title": "Unsafe deserialization",
        "category": "code_pattern",
        "severity": "high",
        "path": "auth.py",
        "line": 4,
    }]

    components = identify_security_sensitive_components(files, sentinel_graph)
    cats = {c["category"] for c in components}
    assert "authentication_authorization" in cats or "api_request_handling" in cats

    paths = reconstruct_defensive_attack_paths(sentinel_graph, files, findings)
    assert len(paths) >= 1
    assert paths[0]["target_file"] == "auth.py"
    assert "POST /api/login" in paths[0]["entry_point"]


def test_multilingual_question_understanding_preserves_technical_identifiers():
    import asyncio
    hinglish_query = "Mere auth/service.py module me koi authenticate_user weakness hai kya?"
    parsed = asyncio.run(understand_multilingual_security_question(hinglish_query, language_code="hi-IN"))

    assert "auth/service.py" in parsed["preserved_entities"]["files"]
    assert "authenticate_user" in parsed["preserved_entities"]["technical_terms"] or "auth/service.py" in parsed["search_terms"]
    assert parsed["detected_intent"] in {"authentication_weakness_review", "general_security_investigation"}


def test_evidence_backed_investigation_flags_unsupported_findings():
    repo_meta = {"full_name": "example/project"}
    query_understanding = {
        "original_question": "Check database injection",
        "detected_intent": "sql_injection_review",
        "search_terms": ["database"],
        "preserved_entities": {"files": ["db.py"]},
        "normalized_english_inquiry": "Check database injection risks",
    }
    sensitive_components = [{"path": "db.py", "category": "database_access", "category_title": "Database Access", "description": "SQL interactions", "sample_lines": [10]}]
    attack_paths = []
    findings = [{
        "id": "finding-sql",
        "title": "Potential SQL string interpolation",
        "category": "code_pattern",
        "severity": "high",
        "path": "db.py",
        "line": 10,
        "evidence": "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
        "recommendation": "Use parameterized queries"
    }]
    evidence_files = [{"path": "db.py", "lines": 25, "language": "python", "excerpt": "0010: cursor.execute('SELECT * FROM users WHERE id=' + uid)"}]

    res = generate_evidence_backed_investigation(
        repo_id="example::project",
        repo_meta=repo_meta,
        query_understanding=query_understanding,
        sensitive_components=sensitive_components,
        attack_paths=attack_paths,
        security_findings=findings,
        neo4j_context=[],
        evidence_files=evidence_files
    )

    assert len(res["investigated_findings"]) == 1
    assert res["investigated_findings"][0]["verification_status"] == "VERIFIED_BY_REPOSITORY_EVIDENCE"
    assert "db.py" in res["report_markdown"]
    assert "Potential SQL string interpolation" in res["report_markdown"]


def test_sqlite_sentinel_investigation_and_status_tracking(tmp_path, monkeypatch):
    database = tmp_path / "sentinel-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    auth.init_auth_db()

    record = {
        "id": "inv-001",
        "repo_id": "test/repo",
        "question": "Is authentication safe?",
        "original_transcript": "",
        "language_code": "en-IN",
        "interpreted_query": "Is authentication safe?",
        "findings": [{"id": "f-1", "title": "Hardcoded secret"}],
        "attack_paths": [],
        "graph_entities": {"total_nodes": 10},
        "evidence": [{"path": "src/auth.py"}],
        "report_markdown": "Report content",
        "remediation": [{"finding_id": "f-1", "status": "open"}],
        "audio_base64": "",
        "created_at": 1000
    }

    auth.save_sentinel_investigation(record, user_id=42)
    loaded = auth.load_sentinel_investigations(repo_id="test/repo")
    assert len(loaded) == 1
    assert loaded[0]["id"] == "inv-001"
    assert loaded[0]["question"] == "Is authentication safe?"

    single = auth.get_sentinel_investigation("inv-001")
    assert single is not None
    assert single["repo_id"] == "test/repo"

    # Status update workflow: Open -> Under Review -> Fixed -> Verified
    auth.update_sentinel_finding_status("test/repo", "f-1", "under_review", "Audited by developer")
    statuses = auth.get_sentinel_finding_statuses("test/repo")
    assert statuses.get("f-1") == "under_review"

    auth.update_sentinel_finding_status("test/repo", "f-1", "verified", "Re-scanned and confirmed safe")
    statuses2 = auth.get_sentinel_finding_statuses("test/repo")
    assert statuses2.get("f-1") == "verified"


def test_sentinel_api_end_to_end():
    client = TestClient(app)
    # Load demo codebase
    demo = client.get("/api/demo")
    assert demo.status_code == 200
    repo_id = demo.json()["id"]

    # Languages endpoint
    lang_res = client.get("/api/sentinel/languages")
    assert lang_res.status_code == 200
    languages = lang_res.json()["languages"]
    assert any(l["code"] == "hi-IN" for l in languages)
    assert any(l["code"] == "en-IN" for l in languages)

    # Repositories endpoint
    repos_res = client.get("/api/sentinel/repos")
    assert repos_res.status_code == 200
    assert len(repos_res.json()["repositories"]) >= 1

    # Multilingual understand query endpoint
    understand_res = client.post("/api/sentinel/understand-query", json={
        "question": "Is repository me credentials exposed hain kya?",
        "language_code": "hi-IN"
    })
    assert understand_res.status_code == 200
    assert "credential" in understand_res.json()["detected_intent"] or "secret" in understand_res.json()["detected_intent"] or "general" in understand_res.json()["detected_intent"]

    # Full Sentinel investigation endpoint
    investigate_res = client.post("/api/sentinel/investigate", json={
        "repo_id": repo_id,
        "question": "Check whether our authentication and orders system has any potential security weaknesses",
        "language_code": "en-IN",
        "speak_response": False
    })
    assert investigate_res.status_code == 200
    data = investigate_res.json()
    assert "stages" in data
    assert len(data["stages"]) >= 5
    assert "findings" in data
    assert "report_markdown" in data
    assert "sensitive_components" in data

    # Overview endpoint
    overview_res = client.get(f"/api/sentinel/overview/{repo_id}")
    assert overview_res.status_code == 200
    assert "sensitive_components" in overview_res.json()
    assert "attack_paths" in overview_res.json()

    # History endpoint
    history_res = client.get(f"/api/sentinel/history?repo_id={repo_id}")
    assert history_res.status_code == 200
    assert len(history_res.json()["items"]) >= 1

    # Finding status patch
    patch_res = client.patch("/api/sentinel/finding/sample-finding/status", json={
        "repo_id": repo_id,
        "status": "under_review",
        "notes": "Checking with engineering lead"
    })
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "under_review"
