from app.security import parse_dependencies, scan_source


def test_secret_detection_redacts_credential_value():
    token = "ghp_" + "A" * 36
    findings = scan_source({"settings.py": f'GITHUB_TOKEN = "{token}"'})
    assert len(findings) >= 1
    assert any(item["severity"] == "critical" for item in findings)
    assert token not in findings[0]["evidence"]
    assert findings[0]["category"] == "secret"


def test_static_security_patterns_are_actionable():
    findings = scan_source({
        "worker.py": "import pickle\npayload = pickle.loads(blob)\nsubprocess.run(command, shell=True)"
    })
    titles = {item["title"] for item in findings}
    assert "Unsafe deserialization" in titles
    assert "Shell execution" in titles


def test_dependency_inventory_reads_exact_pins_only():
    files = {
        "requirements.txt": "fastapi==0.115.2\nhttpx>=0.27\nneo4j==5.26.0\n",
        "package.json": '{"dependencies":{"react":"^18.2.0","lodash":"4.17.21","latest":"latest"}}',
    }
    dependencies = parse_dependencies(files)
    found = {(item["ecosystem"], item["name"], item["version"]) for item in dependencies}
    assert ("PyPI", "fastapi", "0.115.2") in found
    assert ("PyPI", "neo4j", "5.26.0") in found
    assert ("npm", "lodash", "4.17.21") in found
    assert not any(name == "httpx" for _, name, _ in found)
    assert not any(name == "react" for _, name, _ in found)
