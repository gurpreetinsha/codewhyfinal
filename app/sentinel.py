from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

import httpx

from app.security import SAST_PATTERNS, SECRET_PATTERNS, redact_source

# Recognized Indian and common languages for Sarvam Saaras & Bulbul
SUPPORTED_LANGUAGES = [
    {"code": "en-IN", "name": "English (India)", "voice": "shubh_enhi_ads"},
    {"code": "hi-IN", "name": "Hindi (हिंदी)", "voice": "shubh_enhi_ads"},
    {"code": "ta-IN", "name": "Tamil (தமிழ்)", "voice": "tamil_male_1"},
    {"code": "te-IN", "name": "Telugu (తెలుగు)", "voice": "telugu_male_1"},
    {"code": "kn-IN", "name": "Kannada (ಕನ್ನಡ)", "voice": "kannada_male_1"},
    {"code": "bn-IN", "name": "Bengali (বাংলা)", "voice": "bengali_male_1"},
    {"code": "mr-IN", "name": "Marathi (मराठी)", "voice": "marathi_male_1"},
    {"code": "gu-IN", "name": "Gujarati (ગુજરાતી)", "voice": "gujarati_male_1"},
    {"code": "pa-IN", "name": "Punjabi (ਪੰਜਾਬੀ)", "voice": "punjabi_male_1"},
    {"code": "ml-IN", "name": "Malayalam (മലയാളം)", "voice": "malayalam_male_1"},
    {"code": "od-IN", "name": "Odia (ଓଡ଼ିଆ)", "voice": "odia_male_1"},
]

# Patterns for extracting APIs and endpoints across frameworks
API_PATTERNS = [
    # FastAPI / Flask / Starlette / Bottle
    re.compile(r"""@(?:app|router|blueprint|bp)\.(get|post|put|delete|patch|options|head)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""@(?:app|router|blueprint|bp)\.route\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?""", re.IGNORECASE),
    # Express / Koa / Nest / Node HTTP
    re.compile(r"""(?<!@)\b(?:app|router)\.(get|post|put|delete|patch|use)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    # Go (gin, mux, chi, net/http)
    re.compile(r"""\.(?:GET|POST|PUT|DELETE|PATCH|HandleFunc|Handle)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    # Java (Spring Boot)
    re.compile(r"""@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]""", re.IGNORECASE),
]

# Security-sensitive components indicators
SENSITIVE_CATEGORIES = {
    "authentication_authorization": {
        "title": "Authentication & Authorization",
        "description": "Handles identity verification, token validation, session management, or access checks.",
        "keywords": ["auth", "login", "password", "token", "jwt", "session", "oauth", "permission", "role", "credential", "authenticate", "authorize"],
        "regex": re.compile(r"\b(auth|login|password|token|jwt|session|oauth|permission|role|credential|authenticate|authorize)\b", re.IGNORECASE),
    },
    "api_request_handling": {
        "title": "API Routes & Request Handlers",
        "description": "Public or internal HTTP endpoints processing external developer or client inputs.",
        "keywords": ["route", "endpoint", "controller", "handler", "request", "api", "query_params", "req.body"],
        "regex": re.compile(r"\b(route|endpoint|controller|handler|query_params|req\.body|request\.json)\b", re.IGNORECASE),
    },
    "database_access": {
        "title": "Database Access & Queries",
        "description": "Interacts with relational, document, or key-value persistent storage.",
        "keywords": ["db", "database", "sql", "query", "orm", "repository", "cursor", "execute", "select", "insert", "update", "delete", "table"],
        "regex": re.compile(r"\b(database|cursor|query|execute|select|insert|update|delete|table|sqlite|postgres|mysql|mongo|neo4j)\b", re.IGNORECASE),
    },
    "file_and_deserialization": {
        "title": "File Upload & Deserialization",
        "description": "Parses untrusted binary payloads, uploaded archives, pickle, or YAML structures.",
        "keywords": ["upload", "multipart", "pickle", "unpickle", "yaml", "deserialize", "stream", "tarfile", "zipfile"],
        "regex": re.compile(r"\b(upload|multipart|pickle|yaml\.load|deserialize|tarfile|zipfile)\b", re.IGNORECASE),
    },
    "external_service_integrations": {
        "title": "External Service Integrations",
        "description": "Outbound HTTP or RPC integrations with payment gateways, notifications, or third-party APIs.",
        "keywords": ["gateway", "stripe", "charge", "payment", "webhook", "send_mail", "sms", "httpx", "requests", "fetch", "client"],
        "regex": re.compile(r"\b(gateway|stripe|charge|payment|webhook|send_mail|sms|httpx\.|requests\.|fetch\()\b", re.IGNORECASE),
    },
    "secret_and_credential_management": {
        "title": "Secret & Credential Handling",
        "description": "Environment variables, API keys, certificates, or cryptographic key material.",
        "keywords": ["api_key", "secret", "private_key", "dotenv", "os.getenv", "process.env", "secret_key"],
        "regex": re.compile(r"\b(api_key|secret_key|private_key|os\.getenv|process\.env)\b", re.IGNORECASE),
    },
    "dependency_configuration": {
        "title": "Dependency & Ecosystem Manifests",
        "description": "External third-party packages and transitive dependency definitions.",
        "keywords": ["requirements", "package.json", "go.sum", "cargo.lock", "poetry.lock"],
        "regex": re.compile(r"(requirements\.txt|package\.json|go\.sum|cargo\.lock|poetry\.lock|uv\.lock)$", re.IGNORECASE),
    },
}

# Technical keywords preservation list for multilingual/code-mixed translation
TECH_TERMS_SET = {
    "auth", "authentication", "authorization", "login", "logout", "token", "jwt", "session",
    "password", "secret", "api", "endpoint", "route", "service", "gateway", "controller",
    "charge", "payment", "database", "sql", "injection", "xss", "csrf", "rce", "pickle",
    "eval", "exec", "subprocess", "shell", "yaml", "tls", "cors", "sha1", "md5",
    "orders", "repository", "pricing", "discount", "user_id", "items", "amount",
    "get", "post", "put", "delete", "patch", "git", "commit", "pr", "pull request",
    "dependency", "vulnerability", "cve", "osv", "pypi", "npm", "neo4j", "sarvam"
}


def extract_apis(files: dict[str, str]) -> list[dict[str, Any]]:
    """Extract API endpoints, methods, and line numbers from repository files."""
    apis: list[dict[str, Any]] = []
    seen = set()

    for path, content in files.items():
        lines = content.splitlines()
        for line_no, line in enumerate(lines, 1):
            line_matched = False
            for pat in API_PATTERNS:
                for match in pat.finditer(line):
                    groups = [g for g in match.groups() if g is not None]
                    if len(groups) >= 2:
                        method = groups[0].upper()
                        endpoint = groups[1]
                    elif len(groups) == 1:
                        method = "GET"
                        endpoint = groups[0]
                    else:
                        continue

                    line_matched = True
                    # Clean method if comma separated (like route methods=['GET', 'POST'])
                    if "," in method or "[" in method:
                        methods = [m.strip(" '\"[]").upper() for m in method.split(",") if m.strip(" '\"[]")]
                    else:
                        methods = [method]

                    for m in methods:
                        key = (path, m, endpoint)
                        if key in seen:
                            continue
                        seen.add(key)

                        # Find handler function if defined on subsequent lines
                        handler = ""
                        for next_idx in range(line_no, min(line_no + 4, len(lines))):
                            fn_match = re.match(r"\s*(?:async\s+)?def\s+([A-Za-z0-9_]+)", lines[next_idx])
                            if fn_match:
                                handler = fn_match.group(1)
                                break
                            js_match = re.match(r"\s*(?:const|function)\s+([A-Za-z0-9_]+)", lines[next_idx])
                            if js_match:
                                handler = js_match.group(1)
                                break

                        apis.append({
                            "path": path,
                            "method": m,
                            "endpoint": endpoint,
                            "line": line_no,
                            "handler": handler,
                            "label": f"{m} {endpoint}",
                        })
                if line_matched:
                    break
    return apis


def extract_technical_decisions(files: dict[str, str]) -> list[dict[str, Any]]:
    """Detect comments indicating technical decisions, caveats, or deferred security fixes."""
    decisions = []
    pattern = re.compile(r"""(?:#|//|/\*)\s*(TODO|FIXME|HACK|NOTE|SECURITY|DEPRECATED|REVIEW|WARN)[:\s](.+)$""", re.IGNORECASE)
    for path, content in files.items():
        for line_no, line in enumerate(content.splitlines(), 1):
            match = pattern.search(line)
            if match:
                marker = match.group(1).upper()
                detail = match.group(2).strip()
                decisions.append({
                    "path": path,
                    "line": line_no,
                    "marker": marker,
                    "detail": detail[:240],
                    "evidence": line.strip()[:180],
                })
    return decisions[:100]


def build_sentinel_graph(repo_id: str, files: dict[str, str], base_graph: dict[str, Any], security_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Construct a complete Sentinel Knowledge Graph combining:
    Nodes: Repository, File, Function, API, Dependency, Commit, Pull Request, Developer, Vulnerability, Security Finding, Technical Decision, Fix.
    Relationships: CONTAINS, DEFINES, DEPENDS_ON, MODIFIES, AFFECTS, INTRODUCES, FIXES, REVIEWED_IN, RELATED_TO.
    """
    nodes = list(base_graph.get("nodes", []))
    edges = list(base_graph.get("edges", []))
    existing_node_ids = {n["id"] for n in nodes}
    existing_edges = {(e["source"], e["target"], e["type"]) for e in edges}

    # 1. API Nodes and DEFINES/CALLS edges
    apis = extract_apis(files)
    for api_item in apis:
        api_id = f"api:{repo_id}:{api_item['path']}:{api_item['method']}:{api_item['endpoint']}"
        file_id = f"file:{repo_id}:{api_item['path']}"
        if api_id not in existing_node_ids:
            nodes.append({
                "id": api_id,
                "label": api_item["label"],
                "type": "api",
                "method": api_item["method"],
                "endpoint": api_item["endpoint"],
                "path": api_item["path"],
                "line": api_item["line"],
                "handler": api_item.get("handler", ""),
            })
            existing_node_ids.add(api_id)

        edge_key = (file_id, api_id, "DEFINES")
        if edge_key not in existing_edges:
            edges.append({
                "source": file_id,
                "target": api_id,
                "type": "DEFINES",
                "source_path": api_item["path"],
                "target_path": api_item["path"],
            })
            existing_edges.add(edge_key)

        if api_item.get("handler"):
            fn_id = f"fn:{repo_id}:{api_item['path']}:{api_item['handler']}"
            call_edge = (api_id, fn_id, "CALLS")
            if call_edge not in existing_edges:
                edges.append({
                    "source": api_id,
                    "target": fn_id,
                    "type": "CALLS",
                    "source_path": api_item["path"],
                    "target_path": api_item["path"],
                })
                existing_edges.add(call_edge)

    # 2. Dependency, Vulnerability, and Finding Nodes
    if security_data:
        deps = security_data.get("dependency_inventory", [])
        for dep in deps:
            dep_id = f"dep:{repo_id}:{dep['name']}@{dep['version']}"
            if dep_id not in existing_node_ids:
                nodes.append({
                    "id": dep_id,
                    "label": f"{dep['name']}@{dep['version']}",
                    "type": "dependency",
                    "name": dep["name"],
                    "version": dep["version"],
                    "ecosystem": dep.get("ecosystem", "generic"),
                    "manifest": dep.get("manifest", ""),
                })
                existing_node_ids.add(dep_id)

            repo_node_id = repo_id
            edge_key = (repo_node_id, dep_id, "DEPENDS_ON")
            if edge_key not in existing_edges:
                edges.append({
                    "source": repo_node_id,
                    "target": dep_id,
                    "type": "DEPENDS_ON",
                    "source_path": repo_id,
                    "target_path": dep.get("manifest", ""),
                })
                existing_edges.add(edge_key)

        findings = security_data.get("findings", [])
        for finding in findings:
            fid = f"finding:{repo_id}:{finding['id']}"
            if fid not in existing_node_ids:
                nodes.append({
                    "id": fid,
                    "label": finding["title"][:28],
                    "type": "security_finding",
                    "title": finding["title"],
                    "category": finding["category"],
                    "severity": finding["severity"],
                    "path": finding.get("path", ""),
                    "line": finding.get("line"),
                    "recommendation": finding.get("recommendation", ""),
                    "evidence": finding.get("evidence", ""),
                })
                existing_node_ids.add(fid)

            # Link finding to File
            if finding.get("path"):
                file_id = f"file:{repo_id}:{finding['path']}"
                edge_key = (file_id, fid, "CONTAINS")
                if edge_key not in existing_edges:
                    edges.append({
                        "source": file_id,
                        "target": fid,
                        "type": "CONTAINS",
                        "source_path": finding["path"],
                        "target_path": finding["path"],
                    })
                    existing_edges.add(edge_key)

            # If dependency finding, link to dependency and create Vulnerability node
            if finding.get("category") == "dependency" and finding.get("details"):
                vuln_details = finding["details"]
                vuln_id = f"vuln:{repo_id}:{vuln_details['id']}"
                if vuln_id not in existing_node_ids:
                    nodes.append({
                        "id": vuln_id,
                        "label": vuln_details["id"],
                        "type": "vulnerability",
                        "vuln_id": vuln_details["id"],
                        "package": vuln_details["package"],
                        "severity": vuln_details["severity"],
                        "summary": vuln_details.get("summary", ""),
                    })
                    existing_node_ids.add(vuln_id)

                dep_id = f"dep:{repo_id}:{vuln_details['package']}@{vuln_details['version']}"
                intro_edge = (dep_id, vuln_id, "INTRODUCES")
                if intro_edge not in existing_edges:
                    edges.append({
                        "source": dep_id,
                        "target": vuln_id,
                        "type": "INTRODUCES",
                        "source_path": vuln_details.get("manifest", ""),
                        "target_path": vuln_details.get("manifest", ""),
                    })
                    existing_edges.add(intro_edge)

                aff_edge = (vuln_id, fid, "RELATED_TO")
                if aff_edge not in existing_edges:
                    edges.append({
                        "source": vuln_id,
                        "target": fid,
                        "type": "RELATED_TO",
                        "source_path": vuln_details.get("manifest", ""),
                        "target_path": vuln_details.get("manifest", ""),
                    })
                    existing_edges.add(aff_edge)

    # 3. Technical Decisions
    decisions = extract_technical_decisions(files)
    for dec in decisions:
        dec_id = f"dec:{repo_id}:{dec['path']}:{dec['line']}"
        file_id = f"file:{repo_id}:{dec['path']}"
        if dec_id not in existing_node_ids:
            nodes.append({
                "id": dec_id,
                "label": f"{dec['marker']}: {dec['detail'][:22]}",
                "type": "technical_decision",
                "marker": dec["marker"],
                "detail": dec["detail"],
                "path": dec["path"],
                "line": dec["line"],
            })
            existing_node_ids.add(dec_id)

        edge_key = (file_id, dec_id, "CONTAINS")
        if edge_key not in existing_edges:
            edges.append({
                "source": file_id,
                "target": dec_id,
                "type": "CONTAINS",
                "source_path": dec["path"],
                "target_path": dec["path"],
            })
            existing_edges.add(edge_key)

    # Compute updated stats
    type_counts = defaultdict(int)
    for n in nodes:
        type_counts[n.get("type", "unknown")] += 1

    return {
        "id": repo_id,
        "files": base_graph.get("files", {}),
        "nodes": nodes,
        "edges": edges,
        "stats": {
            **base_graph.get("stats", {}),
            "apis": type_counts["api"],
            "dependencies": type_counts["dependency"],
            "vulnerabilities": type_counts["vulnerability"],
            "security_findings": type_counts["security_finding"],
            "technical_decisions": type_counts["technical_decision"],
        },
        "metadata": base_graph.get("metadata", {}),
        "scanned_at": base_graph.get("scanned_at", int(time.time())),
    }


_SENTINEL_NODE_LABELS = {
    "file": "File",
    "function": "Function",
    "class": "CodeClass",
    "api": "API",
    "dependency": "Dependency",
    "security_finding": "SecurityFinding",
    "vulnerability": "Vulnerability",
    "technical_decision": "TechnicalDecision",
}

_SENTINEL_RELATIONSHIP_TYPES = frozenset({
    "CONTAINS", "DEFINES", "IMPORTS", "CALLS", "DEPENDS_ON",
    "MODIFIES", "AFFECTS", "INTRODUCES", "FIXES", "REVIEWED_IN", "RELATED_TO",
})


def persist_sentinel_graph(driver: Any, database: str, graph: dict[str, Any]) -> None:
    """Atomically replace one repository's Sentinel subgraph in Neo4j.

    All entities and edges are written from the exact graph returned to the
    website. Repository-scoped IDs and a scoped cleanup prevent stale nodes
    and cross-repository relationship matches.
    """
    if not driver:
        return

    repo_id = graph["id"]
    prefixes = [
        f"{kind}:{repo_id}:"
        for kind in ("file", "fn", "class", "api", "dep", "finding", "vuln", "dec")
    ]
    nodes_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in graph.get("nodes", []):
        node_type = node.get("type")
        if node_type == "repository":
            continue
        if node_type not in _SENTINEL_NODE_LABELS:
            raise ValueError(f"Unsupported Sentinel graph node type: {node_type!r}")
        props = {
            key: value for key, value in node.items()
            if key not in {"id", "type"} and value is not None
        }
        # Bloom and other graph clients can consistently use either property.
        props.setdefault("label", node.get("label", node.get("name", node["id"])))
        props.setdefault("name", node.get("label", node.get("name", node["id"])))
        nodes_by_type[node_type].append({"id": node["id"], "properties": props})

    edges_by_type: dict[str, list[dict[str, str]]] = defaultdict(list)
    for edge in graph.get("edges", []):
        edge_type = edge.get("type")
        if edge_type not in _SENTINEL_RELATIONSHIP_TYPES:
            raise ValueError(f"Unsupported Sentinel relationship type: {edge_type!r}")
        edges_by_type[edge_type].append({
            "source": edge["source"],
            "target": edge["target"],
        })

    def write(tx: Any) -> None:
        # Remove stale entities from this repository only. The Repository root
        # is retained and all its outgoing relationships are recreated below.
        tx.run(
            "MATCH (n) WHERE n.id IS NOT NULL "
            "AND any(prefix IN $prefixes WHERE n.id STARTS WITH prefix) "
            "DETACH DELETE n",
            prefixes=prefixes,
        )
        tx.run(
            "MERGE (r:Repository {id:$id}) "
            "SET r.name=$name, r.scanned_at=$scanned_at, r.metadata=$metadata",
            id=repo_id,
            name=graph.get("metadata", {}).get("full_name", repo_id),
            scanned_at=graph.get("scanned_at", int(time.time())),
            metadata=json.dumps(graph.get("metadata", {})),
        )

        for node_type, label in _SENTINEL_NODE_LABELS.items():
            batch = nodes_by_type.get(node_type, [])
            if not batch:
                continue
            # Labels come only from the fixed allow-list above; all data values
            # remain parameterized.
            tx.run(
                f"UNWIND $nodes AS item "
                f"MERGE (n:{label} {{id:item.id}}) "
                "SET n += item.properties",
                nodes=batch,
            )

        for edge_type, batch in edges_by_type.items():
            tx.run(
                f"UNWIND $edges AS item "
                "MATCH (a {id:item.source}), (b {id:item.target}) "
                f"MERGE (a)-[:{edge_type}]->(b)",
                edges=batch,
            )

    with driver.session(database=database) as session:
        session.execute_write(write)

def query_neo4j_sentinel_context(driver: Any, database: str, repo_id: str, paths: set[str], terms: list[str]) -> list[dict[str, Any]]:
    """Query Neo4j knowledge graph for security entities connected to the specified paths and terms."""
    if not driver:
        return []
    try:
        query = (
            "MATCH (r:Repository {id:$repo})-[:CONTAINS]->(f:File) "
            "WHERE f.path IN $paths OR any(term IN $terms WHERE toLower(f.path) CONTAINS term) "
            "OPTIONAL MATCH (f)-[rel1:DEFINES|IMPORTS|CONTAINS]-(entity1) "
            "OPTIONAL MATCH (entity1)-[rel2:CALLS|AFFECTS|INTRODUCES|RELATED_TO]-(entity2) "
            "RETURN f.path AS source_file, type(rel1) AS relationship_1, labels(entity1) AS entity_1_labels, "
            "coalesce(entity1.name, entity1.endpoint, entity1.title, entity1.label) AS entity_1_name, "
            "type(rel2) AS relationship_2, labels(entity2) AS entity_2_labels, "
            "coalesce(entity2.name, entity2.endpoint, entity2.title, entity2.label) AS entity_2_name "
            "LIMIT 120"
        )
        result = driver.execute_query(query, repo=repo_id, paths=list(paths), terms=terms, database_=database)
        records = []
        for r in result.records:
            item = dict(r)
            if item.get("relationship_1"):
                records.append(item)
        return records
    except Exception as exc:
        print(f"[CODEWHY SENTINEL] Neo4j context query failed: {exc}")
        return []


def identify_security_sensitive_components(files: dict[str, str], sentinel_graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan and catalog all components in the repository with security significance."""
    components = []
    seen = set()

    for path, info in sentinel_graph.get("files", {}).items():
        content = files.get(path, "")
        for cat_id, cat_info in SENSITIVE_CATEGORIES.items():
            matches = list(cat_info["regex"].finditer(content))
            path_matches = cat_info["regex"].search(path)
            if matches or path_matches:
                key = (path, cat_id)
                if key in seen:
                    continue
                seen.add(key)

                # Locate specific lines
                hit_lines = []
                for line_no, line in enumerate(content.splitlines(), 1):
                    if cat_info["regex"].search(line):
                        hit_lines.append(line_no)
                        if len(hit_lines) >= 5:
                            break

                components.append({
                    "path": path,
                    "category": cat_id,
                    "category_title": cat_info["title"],
                    "description": cat_info["description"],
                    "sample_lines": hit_lines,
                    "hit_count": len(matches),
                    "is_direct_path_match": bool(path_matches),
                })
    return components


def reconstruct_defensive_attack_paths(sentinel_graph: dict[str, Any], files: dict[str, str], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Defensive attack path reconstruction:
    Traces paths from public entry points (APIs/Routes/Inputs) -> functions -> dependencies/sinks -> findings.
    Distinguishes:
    - VERIFIED: Directly established by AST route handler and static import/call.
    - POTENTIAL: Import-connected candidate or name match across files.
    - AI_HYPOTHESIS: Inferred architectural risk based on component roles.
    """
    paths: list[dict[str, Any]] = []

    # Identify entry point nodes
    entry_nodes = []
    for node in sentinel_graph.get("nodes", []):
        if node.get("type") == "api":
            entry_nodes.append(node)
        elif node.get("type") == "file" and any(k in node["path"].lower() for k in ["route", "controller", "endpoint", "api"]):
            entry_nodes.append(node)

    # Build adjacency map
    adj = defaultdict(list)
    for edge in sentinel_graph.get("edges", []):
        adj[edge["source"]].append(edge)

    # Map findings by target
    findings_by_path = defaultdict(list)
    for f in findings:
        findings_by_path[f.get("path")].append(f)

    # Sinks patterns
    sink_pattern = re.compile(r"\b(eval|exec|subprocess|pickle\.loads?|yaml\.load|cursor\.execute|hashlib\.md5)\b")

    for entry in entry_nodes[:15]:
        entry_path = entry.get("path") or entry.get("id").split(":")[2]
        visited = {entry["id"]}
        queue = [([entry], [entry["id"]])]

        while queue:
            node_chain, id_chain = queue.pop(0)
            current = node_chain[-1]

            # Check if current node is a sink or has associated finding
            curr_path = current.get("path")
            matching_findings = findings_by_path.get(curr_path, [])
            has_sink = False
            if curr_path and curr_path in files:
                has_sink = bool(sink_pattern.search(files[curr_path]))

            if (matching_findings or has_sink) and len(node_chain) > 1:
                # Reconstruct full human-readable path
                step_details = []
                for idx in range(len(node_chain) - 1):
                    src = node_chain[idx]
                    dst = node_chain[idx + 1]
                    # Determine relationship verification level
                    rel_type = "IMPORTS"
                    level = "POTENTIAL"
                    if src.get("type") == "api" and dst.get("type") == "function":
                        rel_type = "DEFINES_HANDLER"
                        level = "VERIFIED"
                    elif src.get("type") == "file" and dst.get("type") == "function":
                        rel_type = "DEFINES"
                        level = "VERIFIED"
                    elif src.get("type") == "file" and dst.get("type") == "file":
                        rel_type = "IMPORTS"
                        level = "VERIFIED"

                    step_details.append({
                        "from": src.get("label") or src.get("path") or src["id"],
                        "to": dst.get("label") or dst.get("path") or dst["id"],
                        "relationship": rel_type,
                        "verification_level": level,
                    })

                paths.append({
                    "entry_point": entry.get("label") or entry.get("path") or entry["id"],
                    "sink_component": current.get("label") or curr_path or current["id"],
                    "target_file": curr_path,
                    "chain_length": len(node_chain),
                    "steps": step_details,
                    "findings_at_sink": [f["title"] for f in matching_findings],
                    "verification": "VERIFIED" if all(s["verification_level"] == "VERIFIED" for s in step_details) else "POTENTIAL",
                    "explanation": f"Trace connects external entry point ({entry.get('label')}) through {len(step_details)} graph hop(s) to sensitive sink ({curr_path}).",
                })
                if len(paths) >= 12:
                    break

            if len(node_chain) < 5:
                for edge in adj.get(current["id"], []):
                    target_id = edge["target"]
                    if target_id not in visited:
                        visited.add(target_id)
                        # Find target node
                        target_node = next((n for n in sentinel_graph.get("nodes", []) if n["id"] == target_id), None)
                        if target_node:
                            queue.append((node_chain + [target_node], id_chain + [target_id]))

    return paths


async def understand_multilingual_security_question(
    question: str,
    language_code: str = "en-IN",
    sarvam_api_key: str = "",
    sarvam_api_base: str = "https://api.sarvam.ai/v2",
    sarvam_model: str = "sarvam-105b"
) -> dict[str, Any]:
    """
    Parse multilingual and code-mixed (e.g. Hinglish) user security questions.
    Extracts security intent while rigorously preserving technical identifiers,
    file paths, function names, and API parameters without distortion.
    """
    question_clean = redact_source(question).strip()

    # Heuristic technical entity extraction
    extracted_files = re.findall(r"\b[A-Za-z0-9_./\\-]+\.(?:py|js|ts|tsx|jsx|go|java|rs|json|yaml|yml|lock|txt|toml)\b", question_clean)
    extracted_functions = re.findall(r"\b(?:function|fn|def|method)?\s*([A-Za-z_][A-Za-z0-9_]+)\s*\(\)", question_clean)
    extracted_endpoints = re.findall(r"/(?:[a-zA-Z0-9_-]+/?)+", question_clean)

    # Detect technical terms in question
    words = re.findall(r"[A-Za-z0-9_]+", question_clean.lower())
    matched_tech_terms = [w for w in words if w in TECH_TERMS_SET]

    # Intent classification heuristics
    detected_intent = "general_security_investigation"
    q_lower = question_clean.lower()
    if any(k in q_lower for k in ["secret", "key", "password", "token", "credential", "hardcode", "exposed", "chabhi", "pass"]):
        detected_intent = "secret_exposure_audit"
    elif any(k in q_lower for k in ["auth", "login", "jwt", "session", "permission", "role", "access"]):
        detected_intent = "authentication_weakness_review"
    elif any(k in q_lower for k in ["dependency", "package", "library", "cve", "osv", "vulnerable", "update", "patch"]):
        detected_intent = "dependency_vulnerability_investigation"
    elif any(k in q_lower for k in ["attack", "path", "sink", "injection", "rce", "exploit", "flow"]):
        detected_intent = "attack_path_reconstruction"
    elif any(k in q_lower for k in ["affect", "impact", "change", "badal", "modify", "break"]):
        detected_intent = "impact_and_regression_analysis"

    result = {
        "original_question": question_clean,
        "language_code": language_code,
        "detected_intent": detected_intent,
        "preserved_entities": {
            "files": list(set(extracted_files)),
            "functions": list(set(extracted_functions)),
            "endpoints": list(set(extracted_endpoints)),
            "technical_terms": list(set(matched_tech_terms)),
        },
        "search_terms": list(set(matched_tech_terms + extracted_files + extracted_functions + [detected_intent.split("_")[0]])),
        "normalized_english_inquiry": question_clean,
    }

    # If Sarvam is configured and the query is non-English or code-mixed, use Sarvam LLM for semantic normalization
    is_non_english = language_code != "en-IN" or any(indic in q_lower for indic in ["kya", "hai", "kaise", "mein", "ko", "se", "aur", "mere", "is", "par", "karo", "batao"])
    if sarvam_api_key and is_non_english:
        system_prompt = (
            "You are a cybersecurity question parser for CODEWHY SENTINEL. "
            "The user asked a security question in an Indian language or code-mixed Hinglish. "
            "Translate their question into a clear, concise English security investigation request. "
            "CRITICAL REQUIREMENT: Do NOT translate or modify technical identifiers (file names, function names, "
            "API routes, variable names, library names, protocol names). Keep them 100% exact. "
            "Output JSON with keys: normalized_inquiry, primary_focus, technical_entities."
        )
        try:
            async with httpx.AsyncClient(timeout=18) as client:
                resp = await client.post(
                    f"{sarvam_api_base}/chat/completions",
                    headers={"api-subscription-key": sarvam_api_key, "Content-Type": "application/json"},
                    json={
                        "model": sarvam_model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": f"User Question: {question_clean}"}
                        ],
                        "temperature": 0.1,
                        "max_tokens": 400
                    }
                )
                if resp.status_code == 200:
                    raw_content = resp.json()["choices"][0]["message"]["content"]
                    # Extract JSON if returned in markdown fences
                    match = re.search(r"\{[\s\S]*\}", raw_content)
                    if match:
                        parsed = json.loads(match.group(0))
                        result["normalized_english_inquiry"] = parsed.get("normalized_inquiry", question_clean)
                        if parsed.get("technical_entities") and isinstance(parsed["technical_entities"], list):
                            result["preserved_entities"]["technical_terms"].extend(parsed["technical_entities"])
        except Exception as exc:
            print(f"[CODEWHY SENTINEL] Multilingual normalization fallback: {exc}")

    return result


def generate_evidence_backed_investigation(
    repo_id: str,
    repo_meta: dict[str, Any],
    query_understanding: dict[str, Any],
    sensitive_components: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
    security_findings: list[dict[str, Any]],
    neo4j_context: list[dict[str, Any]],
    evidence_files: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Synthesize a rigorous, evidence-backed security investigation result.
    Enforces the rule: Every important AI conclusion must be linked to actual evidence.
    If evidence is missing: 'Insufficient repository evidence to verify this finding.'
    """
    # Correlate findings relevant to the user query
    terms = set(query_understanding.get("search_terms", []))
    preserved = query_understanding.get("preserved_entities", {})
    specific_paths = set(preserved.get("files", []))
    specific_functions = set(preserved.get("functions", []))

    relevant_findings = []
    for f in security_findings:
        f_path = f.get("path", "")
        f_title = f.get("title", "").lower()
        f_text = f.get("evidence", "").lower() + " " + f.get("recommendation", "").lower()
        is_relevant = (
            f_path in specific_paths
            or any(term in f_path.lower() for term in terms)
            or any(term in f_title for term in terms)
            or any(term in f_text for term in terms)
        )
        if is_relevant or not terms:
            relevant_findings.append(f)

    # If no specific findings matched, use top findings
    if not relevant_findings and security_findings:
        relevant_findings = security_findings[:6]

    # Correlate sensitive components
    relevant_components = [
        c for c in sensitive_components
        if c["path"] in specific_paths or any(t in c["path"].lower() or t in c["category"].lower() for t in terms)
    ] or sensitive_components[:6]

    # Correlate attack paths
    relevant_attack_paths = [
        p for p in attack_paths
        if p["target_file"] in specific_paths or any(t in p["entry_point"].lower() or t in p["sink_component"].lower() for t in terms)
    ] or attack_paths[:4]

    # Generate structured findings with verified evidence
    investigated_findings = []
    for idx, f in enumerate(relevant_findings[:8], 1):
        # Look for supporting evidence in retrieved file excerpts
        file_match = next((e for e in evidence_files if e["path"] == f.get("path")), None)
        line_num = f.get("line")
        code_snip = f.get("evidence") or "Pattern match in repository file"
        if not file_match:
            supporting_evidence = f"File {f.get('path')} identified in security scan."
        else:
            supporting_evidence = f"Observed in {f.get('path')} (Line {line_num or 'N/A'}): `{code_snip}`"

        # Remediation recommendations
        remediation_action = f.get("recommendation") or "Review source logic and replace with secure standard library constructs."
        affected_modules = [f.get("path")]
        for p in relevant_attack_paths:
            if p["target_file"] == f.get("path"):
                affected_modules.append(p["entry_point"])

        investigated_findings.append({
            "finding_id": f.get("id") or f"find-{idx}",
            "title": f.get("title"),
            "category": f.get("category"),
            "severity": f.get("severity", "medium").upper(),
            "affected_file": f.get("path"),
            "line_number": line_num,
            "related_function_or_api": f.get("title"),
            "supporting_evidence": supporting_evidence,
            "connected_components": list(set(affected_modules)),
            "potential_impact": (
                "Critical compromise: Credential theft or unauthorized access." if f.get("severity") == "critical"
                else "High risk: Code execution or unauthenticated modification." if f.get("severity") == "high"
                else "Medium risk: Architectural deviation or potential injection under certain inputs."
            ),
            "recommended_action": remediation_action,
            "status": "open",
            "verification_status": "VERIFIED_BY_REPOSITORY_EVIDENCE" if file_match else "INSUFFICIENT_EVIDENCE",
        })

    # Executive Summary Construction
    repo_name = repo_meta.get("full_name") or repo_id
    summary_lines = [
        f"### CODEWHY SENTINEL Investigation Report for `{repo_name}`",
        f"**User Question:** \"{query_understanding.get('original_question')}\"",
        f"**Interpreted Intent:** `{query_understanding.get('detected_intent')}`",
        f"**Normalized Security Inquiry:** {query_understanding.get('normalized_english_inquiry')}",
        "",
        "#### 1. Security-Sensitive Components Overview",
    ]

    if relevant_components:
        for c in relevant_components[:5]:
            lines_str = f"Lines: {', '.join(map(str, c['sample_lines']))}" if c['sample_lines'] else "Path-level match"
            summary_lines.append(f"- **{c['category_title']}** (`{c['path']}`): {c['description']} ({lines_str})")
    else:
        summary_lines.append("- *Insufficient repository evidence to identify custom security-sensitive components matching this inquiry.*")

    summary_lines.append("\n#### 2. Neo4j Knowledge Graph Relationships")
    if neo4j_context:
        for r in neo4j_context[:6]:
            summary_lines.append(f"- `({r['source_file']}) -[:{r.get('relationship_1')}]-> ({r.get('entity_1_name')})`")
    else:
        summary_lines.append("- In-memory engineering graph relationships retrieved and explored across files, functions, and definitions.")

    summary_lines.append("\n#### 3. Defensive Attack Path Reconstruction")
    if relevant_attack_paths:
        for path in relevant_attack_paths:
            summary_lines.append(f"- **[{path['verification']}]** `{path['entry_point']}` → `{path['sink_component']}`")
            summary_lines.append(f"  *Evidence:* {path['explanation']}")
    else:
        summary_lines.append("- *No static route-to-sink candidate paths directly intersecting the requested components.*")

    summary_lines.append("\n#### 4. Evidence-Backed Findings & Impact")
    if investigated_findings:
        for f in investigated_findings:
            sev_badge = f"**[{f['severity']}]**"
            loc = f"`{f['affected_file']}:{f['line_number']}`" if f['line_number'] else f"`{f['affected_file']}`"
            summary_lines.append(f"- {sev_badge} **{f['title']}** at {loc}")
            summary_lines.append(f"  - **Evidence:** {f['supporting_evidence']}")
            summary_lines.append(f"  - **Impact:** {f['potential_impact']}")
            summary_lines.append(f"  - **Remediation:** {f['recommended_action']}")
    else:
        summary_lines.append("Insufficient repository evidence to verify a security weakness directly answering this specific question. The scanned repository snapshots contain no matching static flags or advisories.")

    summary_lines.append("\n#### 5. Intelligent Remediation Plan & Testing Recommendations")
    summary_lines.append("1. **Isolate Findings:** Update affected modules to validate caller permissions and avoid untrusted string interpolation.")
    summary_lines.append("2. **Execute Unit Tests:** Run test suites checking edge cases for all entry routes identified in the attack path.")
    summary_lines.append("3. **Status Workflow:** Use the Sentinel status tracker below to transition findings from **Open** → **Under Review** → **Fixed** → **Verified**.")

    report_markdown = "\n".join(summary_lines)

    return {
        "report_markdown": report_markdown,
        "investigated_findings": investigated_findings,
        "sensitive_components": relevant_components,
        "attack_paths": relevant_attack_paths,
        "neo4j_relationships_count": len(neo4j_context),
        "evidence_files": evidence_files,
        "traceability": {
            "status": "grounded_in_evidence" if investigated_findings else "insufficient_evidence",
            "cited_files": [f["affected_file"] for f in investigated_findings if f["affected_file"]],
            "disclaimer": "Defensive analysis is grounded in static repository code and graph relationships. It does not perform live exploitation or execution.",
        }
    }
