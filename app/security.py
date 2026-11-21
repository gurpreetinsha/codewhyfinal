from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import PurePosixPath
from typing import Any

import httpx

SECRET_PATTERNS = [
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), "critical"),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("Stripe live secret", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "critical"),
    ("Environment credential assignment", re.compile(r"(?i)^\s*[A-Z0-9_]*(?:API[_-]?KEY|CLIENT[_-]?SECRET|SECRET[_-]?ACCESS[_-]?KEY|PASSWORD|PASSWD|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN)\s*=\s*(?!\s*$)(?!\$\{)[A-Za-z0-9_./+=-]{12,}\s*$"), "high"),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("JWT-like token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"), "high"),
    ("Hard-coded credential assignment", re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "high"),
]

SAST_PATTERNS = [
    ("Dynamic code execution", re.compile(r"\b(?:eval|exec)\s*\("), "high", "Untrusted input reaching dynamic execution can lead to code execution. Review the input source and use a safe parser or explicit dispatch."),
    ("Unsafe deserialization", re.compile(r"\bpickle\.(?:loads?|Unpickler)\s*\("), "high", "Deserializing untrusted pickle data can execute attacker-controlled code. Use a data-only format for untrusted input."),
    ("Shell execution", re.compile(r"subprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*shell\s*=\s*True"), "high", "Shell execution with interpolated input can enable command injection. Prefer argument arrays and avoid shell=True."),
    ("TLS verification disabled", re.compile(r"(?:requests\.|httpx\.)[^\n]*verify\s*=\s*False"), "high", "TLS certificate verification is disabled. This can expose traffic to interception."),
    ("Unsafe YAML loading", re.compile(r"yaml\.load\s*\((?![^\n]*SafeLoader)"), "medium", "yaml.load without a safe loader may construct arbitrary Python objects. Use yaml.safe_load for untrusted YAML."),
    ("Weak password hash", re.compile(r"hashlib\.(?:md5|sha1)\s*\("), "medium", "MD5/SHA-1 are unsuitable for password storage. Use Argon2id, scrypt, or bcrypt with an appropriate work factor."),
    ("Potential SQL string interpolation", re.compile(r"(?i)(?:execute|executemany)\s*\(\s*(?:f['\"]|['\"][^'\"]*%s)"), "high", "SQL built through string interpolation can be injectable. Use parameterized queries."),
    ("Wildcard CORS", re.compile(r"(?i)(?:allow_origins|Access-Control-Allow-Origin)[^\n]*(?:\[\s*['\"]\*['\"]|['\"]\*['\"])"), "medium", "Wildcard CORS may expose browser-accessible APIs to arbitrary origins. Restrict origins where credentials or sensitive data are involved."),
]

def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-3:]

def scan_source(files: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for path, content in files.items():
        for line_no, line in enumerate(content.splitlines(), 1):
            safe_line = line
            for _, secret_pattern, _ in SECRET_PATTERNS:
                safe_line = secret_pattern.sub(lambda m: _mask(m.group(0)), safe_line)
            for title, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    raw = match.group(0)
                    key = (path, line_no, title)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": hashlib.sha256(f"{path}:{line_no}:{title}".encode()).hexdigest()[:12],
                        "category": "secret",
                        "severity": severity,
                        "title": title,
                        "path": path,
                        "line": line_no,
                        "evidence": _mask(raw),
                        "fingerprint": hashlib.sha256(raw.encode()).hexdigest()[:12],
                        "recommendation": "Revoke and rotate the credential, remove it from source history where appropriate, and load it from a secret manager or environment variable.",
                        "confidence": "high",
                    })
            for title, pattern, severity, recommendation in SAST_PATTERNS:
                if pattern.search(line):
                    key = (path, line_no, title)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "id": hashlib.sha256(f"{path}:{line_no}:{title}".encode()).hexdigest()[:12],
                        "category": "code_pattern",
                        "severity": severity,
                        "title": title,
                        "path": path,
                        "line": line_no,
                        "evidence": safe_line.strip()[:180],
                        "recommendation": recommendation,
                        "confidence": "review",
                    })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (order.get(x["severity"], 9), x["path"], x["line"]))
    return findings[:300]

def parse_dependencies(files: dict[str, str]) -> list[dict[str, str]]:
    deps: dict[tuple[str, str], dict[str, str]] = {}
    for path, content in files.items():
        name = PurePosixPath(path).name.lower()
        if name in {"requirements.txt", "requirements-dev.txt", "requirements.lock"}:
            for raw in content.splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", "-", "git+", "http")):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9_.+-]+)", line)
                if match:
                    package, version = match.groups()
                    deps[("PyPI", package.lower())] = {"ecosystem": "PyPI", "name": package, "version": version, "manifest": path}
        elif name == "package.json":
            try:
                data = json.loads(content)
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    for package, raw_version in (data.get(section) or {}).items():
                        version = str(raw_version).strip()
                        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                            deps[("npm", package.lower())] = {"ecosystem": "npm", "name": package, "version": version, "manifest": path}
            except (ValueError, TypeError):
                pass
        elif name == "package-lock.json":
            try:
                data = json.loads(content)
                for package_path, item in (data.get("packages") or {}).items():
                    if not package_path or "node_modules/" not in package_path:
                        continue
                    package = item.get("name") or package_path.split("node_modules/")[-1]
                    version = str(item.get("version", ""))
                    if package and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                        deps[("npm", package.lower())] = {"ecosystem": "npm", "name": package, "version": version, "manifest": path}
            except (ValueError, TypeError):
                pass
        elif name in {"poetry.lock", "uv.lock", "cargo.lock"}:
            try:
                data = tomllib.loads(content)
                entries = data.get("package") or data.get("packages") or []
                ecosystem = "crates.io" if name == "cargo.lock" else "PyPI"
                for item in entries:
                    package, version = item.get("name"), str(item.get("version", ""))
                    if package and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                        deps[(ecosystem, package.lower())] = {"ecosystem": ecosystem, "name": package, "version": version, "manifest": path}
            except (ValueError, TypeError):
                pass
        elif name == "go.sum":
            for line in content.splitlines():
                parts = line.split()
                if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
                    version = parts[1].split("/")[0]
                    if re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                        deps[("Go", parts[0].lower())] = {"ecosystem": "Go", "name": parts[0], "version": version, "manifest": path}
    return list(deps.values())[:500]

async def check_osv(dependencies: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if not dependencies:
        return [], []
    queries = [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in dependencies]
    vulnerabilities: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    async with httpx.AsyncClient(timeout=22) as client:
        for start in range(0, len(queries), 100):
            batch = queries[start:start + 100]
            try:
                response = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": batch})
                response.raise_for_status()
                results = response.json().get("results", [])
            except (httpx.HTTPError, ValueError):
                skipped.extend(dependencies[start:start + len(batch)])
                continue
            for dep, result in zip(dependencies[start:start + len(batch)], results):
                for vuln in result.get("vulns", []):
                    affected = vuln.get("affected", [])
                    fixed = []
                    for item in affected:
                        for rng in item.get("ranges", []):
                            fixed.extend(event["fixed"] for event in rng.get("events", []) if event.get("fixed"))
                    db_severity = (vuln.get("database_specific") or {}).get("severity", "MEDIUM").upper()
                    severity = db_severity if db_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
                    vulnerabilities.append({
                        "id": vuln.get("id", "UNKNOWN"),
                        "aliases": vuln.get("aliases", [])[:5],
                        "package": dep["name"],
                        "ecosystem": dep["ecosystem"],
                        "version": dep["version"],
                        "manifest": dep["manifest"],
                        "severity": severity.lower(),
                        "summary": (vuln.get("summary") or vuln.get("details") or "Known vulnerability in this dependency.")[:400],
                        "fixed_versions": sorted(set(fixed))[:5],
                        "references": [x.get("url") for x in vuln.get("references", [])[:3] if x.get("url")],
                        "source": "OSV",
                    })
    return vulnerabilities, skipped

async def security_report(files: dict[str, str]) -> dict[str, Any]:
    code_findings = scan_source(files)
    dependencies = parse_dependencies(files)
    vulnerabilities, skipped = await check_osv(dependencies)
    findings = code_findings + [{
        "id": v["id"], "category": "dependency", "severity": v["severity"], "title": v["id"],
        "path": v["manifest"], "line": None, "evidence": f'{v["package"]}@{v["version"]}',
        "recommendation": ("Upgrade to " + ", ".join(v["fixed_versions"]) if v["fixed_versions"] else "Review the advisory and update to a verified patched release."),
        "confidence": "known_advisory", "details": v,
    } for v in vulnerabilities]
    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in ("critical", "high", "medium", "low")}
    score = max(0, 100 - counts["critical"] * 25 - counts["high"] * 12 - counts["medium"] * 5 - counts["low"] * 1)
    return {
        "findings": findings,
        "summary": {"total": len(findings), "by_severity": counts, "risk_score": score, "dependencies_checked": len(dependencies), "vulnerable_dependencies": len(vulnerabilities)},
        "dependency_inventory": dependencies,
        "osv_unavailable_for": skipped,
        "methodology": "Static pattern checks and OSV advisories for exact versions detected in supported manifests. Findings require human review; absence of findings is not proof of security.",
    }
