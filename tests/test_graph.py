from app.main import attack_path_report, build_graph, impact_report


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
