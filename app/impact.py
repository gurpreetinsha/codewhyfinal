"""
CODEWHY - Feature 4.2: AI Change Impact Analyzer (CORRECTED)
Fixes:
1. Reconstructs patched file before running AST parser (No SyntaxError on diffs).
2. Strips 'a/' and 'b/' git prefixes so file paths match repository keys.
3. Accurate blast radius calculation across direct and transitive graph dependents.
"""
from __future__ import annotations

import ast
import io
import json
import re
from collections import defaultdict
from typing import Any

from unidiff import PatchSet
from app.security import scan_source


def _normalize_path(path: str) -> str:
    """Strips leading a/, b/, or ./ from git diff paths."""
    p = path.strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p.lstrip("./")


def parse_diff_components(diff_text: str) -> dict[str, Any]:
    """Parses unified git diff with path normalization and hunk line extraction."""
    added_files = []
    removed_files = []
    modified_files = []
    file_patches: dict[str, Any] = {}

    try:
        patch = PatchSet(io.StringIO(diff_text))
        for patched_file in patch:
            norm_path = _normalize_path(patched_file.path)
            if patched_file.is_added_file:
                added_files.append(norm_path)
            elif patched_file.is_removed_file:
                removed_files.append(norm_path)
            else:
                modified_files.append(norm_path)
            file_patches[norm_path] = patched_file
    except Exception:
        # Fallback if unidiff fails on incomplete header
        for m in re.finditer(r"^\+\+\+ [b/]*(.+)$", diff_text, re.M):
            p = _normalize_path(m.group(1))
            if p not in modified_files:
                modified_files.append(p)

    all_paths = sorted(set(added_files + modified_files + removed_files))
    return {
        "added_files": added_files,
        "removed_files": removed_files,
        "modified_files": modified_files,
        "all_changed_paths": all_paths,
        "file_patches": file_patches
    }


def extract_code_signatures(content: str) -> dict[str, dict[str, Any]]:
    """Extracts function definitions, argument lists, and lines using AST."""
    signatures = {}
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                signatures[node.name] = {
                    "args": [a.arg for a in node.args.args],
                    "arg_count": len(node.args.args),
                    "line": node.lineno
                }
    except SyntaxError:
        pass
    return signatures


def reconstruct_new_file(old_content: str, patched_file) -> str:
    """
    Applies diff hunks to the old file content from bottom to top
    to reconstruct the valid new Python file without diff markers.
    """
    if not patched_file or not hasattr(patched_file, "__iter__"):
        return old_content
        
    old_lines = old_content.splitlines(keepends=True)
    try:
        # Reverse hunks so line numbers in earlier hunks stay valid
        for hunk in reversed(list(patched_file)):
            src_start = max(0, hunk.source_start - 1)
            src_len = hunk.source_length
            target_lines = [line.value for line in hunk if not line.is_removed]
            old_lines[src_start:src_start + src_len] = target_lines
        return "".join(old_lines)
    except Exception:
        # Fallback: extract added lines directly
        added_lines = [line.value for hunk in patched_file for line in hunk if line.is_added]
        return old_content + "\n" + "".join(added_lines)


def detect_ast_changes(old_content: str, patched_file) -> dict[str, Any]:
    """Compares AST of old file with AST of reconstructed new file."""
    old_sigs = extract_code_signatures(old_content)
    new_content = reconstruct_new_file(old_content, patched_file)
    new_sigs = extract_code_signatures(new_content)

    # If new_sigs could not be parsed, don't falsely claim all old functions were deleted!
    if not new_sigs and old_sigs:
        return {
            "added_functions": [],
            "removed_functions": [],
            "modified_signatures": [],
            "note": "Partial diff; could not reconstruct full AST. Checked syntax safely."
        }

    added_functions = [fn for fn in new_sigs if fn not in old_sigs]
    removed_functions = [fn for fn in old_sigs if fn not in new_sigs]
    modified_signatures = []

    for fn in old_sigs:
        if fn in new_sigs:
            if old_sigs[fn]["arg_count"] != new_sigs[fn]["arg_count"]:
                modified_signatures.append({
                    "function": fn,
                    "old_args": old_sigs[fn]["args"],
                    "new_args": new_sigs[fn]["args"],
                    "issue": f"Function '{fn}' arguments changed from {old_sigs[fn]['args']} to {new_sigs[fn]['args']}."
                })

    return {
        "added_functions": added_functions,
        "removed_functions": removed_functions,
        "modified_signatures": modified_signatures
    }


def calculate_blast_radius(graph: dict[str, Any], changed_paths: list[str]) -> dict[str, Any]:
    """Traces reverse IMPORTS & CALLS to compute direct and transitive ripple effects."""
    direct_dependents: set[str] = set()
    transitive_dependents: set[str] = set()
    edges = graph.get("edges", [])

    adjacency = defaultdict(set)
    for e in edges:
        if e.get("type") in {"IMPORTS", "CALLS"}:
            src = e.get("source_path") or e.get("source", "").removeprefix("file:").split(":")[-1]
            tgt = e.get("target_path") or e.get("target", "").removeprefix("file:").split(":")[-1]
            if src and tgt:
                adjacency[tgt].add(src)

    for p in changed_paths:
        for dep in adjacency.get(p, set()):
            if dep not in changed_paths:
                direct_dependents.add(dep)

    queue = list(direct_dependents)
    visited = set(direct_dependents) | set(changed_paths)
    hops = 0
    while queue and hops < 50:
        hops += 1
        curr = queue.pop(0)
        for parent in adjacency.get(curr, set()):
            if parent not in visited:
                visited.add(parent)
                transitive_dependents.add(parent)
                queue.append(parent)

    total_files = max(1, len(graph.get("files", {})))
    affected_count = len(direct_dependents) + len(transitive_dependents)
    blast_score = min(100, int((affected_count / total_files) * 100))

    return {
        "direct_dependents": sorted(direct_dependents),
        "transitive_dependents": sorted(transitive_dependents),
        "affected_count": affected_count,
        "blast_score": blast_score,
        "level": "CRITICAL" if blast_score > 40 else "HIGH" if blast_score > 20 else "LOW"
    }


def analyze_change_impact(
    description: str,
    diff_text: str,
    graph: dict[str, Any]
) -> dict[str, Any]:
    diff_info = parse_diff_components(diff_text)
    changed_paths = diff_info["all_changed_paths"]
    files = graph.get("files", {})
    component_changes = {}

    for path in changed_paths:
        if path in files and path.endswith(".py"):
            old_code = files[path].get("content", "")
            patched_file = diff_info["file_patches"].get(path)
            component_changes[path] = detect_ast_changes(old_code, patched_file)

    impact = calculate_blast_radius(graph, changed_paths)
    security_issues = scan_source({"proposed_change.diff": diff_text})

    missing_tests = []
    has_test_in_diff = any("test" in cp.lower() for cp in changed_paths)
    for p in changed_paths:
        if "test" not in p.lower() and (p.startswith("src/") or p.startswith("app/")):
            if not has_test_in_diff:
                missing_tests.append(f"No corresponding test modified for core module: {p}")

    breaking_changes = []
    for path, changes in component_changes.items():
        for mod in changes.get("modified_signatures", []):
            breaking_changes.append(f"{path} -> {mod['issue']}")
        for rem in changes.get("removed_functions", []):
            breaking_changes.append(f"{path}: Deleted function '{rem}' will break external callers.")

    recommendations = []
    for dep in impact["direct_dependents"][:4]:
        recommendations.append(f"Execute regression test suite on: {dep}")
    if missing_tests:
        recommendations.append("Author unit tests covering the newly altered execution paths.")
    if security_issues:
        recommendations.append("Remediate static security patterns detected in the proposed patch.")

    return {
        "description": description,
        "changed_files_count": len(changed_paths),
        "changed_paths": changed_paths,
        "blast_radius": impact,
        "component_changes": component_changes,
        "breaking_changes": breaking_changes,
        "security_findings": security_issues,
        "missing_tests": missing_tests,
        "recommendations": recommendations,
        "risk_level": "HIGH" if (breaking_changes or impact["blast_score"] > 30) else "MODERATE" if impact["blast_score"] > 10 else "LOW"
    }
