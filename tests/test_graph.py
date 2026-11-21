from fastapi.testclient import TestClient

from app.main import app, attack_path_report, build_graph, impact_report


def test_graph_nodes_are_namespaced_and_impact_is_repo_local():
    files = {
        "api.py": 'from service import risky\n@app.get("/run")\ndef route():\n    return risky()\n',
        "service.py": "def risky(value):\n    return eval(value)\n",
    }
    first = build_graph("alice::org/repo", files)
    second = build_graph("bob::org/repo", files)
    first_ids = {node["id"] for node in first["nodes"]}
    second_ids = {node["id"] for node in second["nodes"]}
    assert first_ids.isdisjoint(second_ids)
    impact = impact_report(first, "service.py")
    assert impact["direct_dependents"] == ["api.py"]
    assert impact["count"] == 1


def test_attack_path_is_labelled_as_a_candidate_not_proof():
    files = {
        "api.py": '@app.post("/run")\ndef route(request):\n    return risky()\nfrom service import risky\n',
        "service.py": "def risky(value):\n    return eval(value)\n",
    }
    graph = build_graph("team::org/repo", files)
    candidates = attack_path_report(graph, [])
    assert len(candidates) == 1
    assert candidates[0]["path"] == ["api.py", "service.py"]
    assert "does not prove data flow" in candidates[0]["evidence"]

def test_demo_routes_and_security_scan_work_end_to_end():
    client = TestClient(app)
    demo = client.get("/api/demo")
    assert demo.status_code == 200
    repo_id = demo.json()["id"]
    graph = client.get("/api/repos/" + repo_id + "/graph")
    assert graph.status_code == 200
    assert graph.json()["stats"]["files"] > 0
    impact = client.post("/api/repos/" + repo_id + "/impact", json={"path": "src/payments/gateway.py"})
    assert impact.status_code == 200
    assert "src/orders/service.py" in impact.json()["direct_dependents"]
    security = client.post("/api/repos/" + repo_id + "/security/scan")
    assert security.status_code == 200
    assert "attack_paths" in security.json()
    assert security.json()["timeline_delta"]["new_count"] >= 0
    timeline = client.get("/api/repos/" + repo_id + "/security-history")
    assert timeline.status_code == 200
    assert len(timeline.json()["items"]) >= 1

def test_anonymous_repository_workspaces_are_isolated():
    first_client = TestClient(app)
    second_client = TestClient(app)
    first_repo = first_client.get("/api/demo").json()["id"]
    path = "/api/repos/" + first_repo + "/graph"
    assert first_client.get(path).status_code == 200
    assert second_client.get(path).status_code == 404
