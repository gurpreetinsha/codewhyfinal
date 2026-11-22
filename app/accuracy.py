"""
CODEWHY - Feature 4.1: AI Accuracy Generator & Evidence Evaluator (CORRECTED)
Fixes:
1. Regex matches functions with/without parentheses, backticks, or 'def/function'.
2. Semantic Concept Matching: Claims are NOT verified just because a file exists;
   core action words and symbols must be present in the file content.
3. Git Commit verification: Uses commit history to verify historical claims.
4. Answer Self-Correction: Generates refinement prompts when confidence is low.
"""
from __future__ import annotations

import re
from typing import Any

STOP_WORDS = {
    "the", "and", "this", "that", "with", "from", "into", "file", "code", "does",
    "will", "which", "then", "when", "what", "where", "have", "been", "using",
    "function", "class", "module", "system", "data", "user", "call", "calls"
}


def _extract_claims(answer: str) -> list[dict[str, Any]]:
    sentences = re.split(r"(?<=[.!?])\s+", answer.strip())
    claims = []

    file_pattern = re.compile(r"([A-Za-z0-9_\-./]+\.(?:py|js|ts|jsx|tsx|json|yml|yaml|go|rs|java))")
    func_pattern = re.compile(r"(?:`([A-Za-z_][A-Za-z0-9_]*)`|(?:def|function|method)\s+([A-Za-z_][A-Za-z0-9_]*)\b|\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\))")

    for sentence in sentences:
        s = sentence.strip()
        if not s or len(s) < 15:
            continue

        referenced_files = file_pattern.findall(s)
        raw_funcs = func_pattern.findall(s)
        referenced_funcs = [next(f for f in match if f) for match in raw_funcs if any(match)]

        category = "generic_claim"
        if referenced_files and referenced_funcs:
            category = "function_in_file"
        elif referenced_files:
            category = "file_assertion"
        elif referenced_funcs:
            category = "function_assertion"
        elif any(w in s.lower() for w in ["commit", "author", "merged", "history", "pr"]):
            category = "historical_claim"
        elif any(w in s.lower() for w in ["security", "vulnerability", "auth", "token", "secret", "inject"]):
            category = "security_assertion"

        claims.append({
            "statement": s,
            "category": category,
            "referenced_files": referenced_files,
            "referenced_functions": referenced_funcs,
            "status": "unverified",
            "evidence": "",
            "confidence_weight": 1.0 if category != "generic_claim" else 0.5
        })

    return claims[:12]


def _verify_code_claim(claim: dict[str, Any], files: dict[str, Any]) -> tuple[str, str]:
    """
    Performs true content inspection instead of blindly accepting file existence.
    """
    claimed_files = claim["referenced_files"]
    claimed_funcs = claim["referenced_functions"]
    statement = claim["statement"].lower()

    if not claimed_files and not claimed_funcs:
        return "neutral", "General explanation without specific code entities."

    # Verify Files & Content
    for p in claimed_files:
        norm_path = p.lstrip("./")
        matched_key = next((k for k in files if k.endswith(norm_path) or norm_path.endswith(k)), None)

        if not matched_key:
            return "hallucination", f"Hallucination: File '{p}' does not exist in repository."

        file_info = files[matched_key]
        content = file_info.get("content", "").lower()
        declared_funcs = [f["name"].lower() for f in file_info.get("functions", [])]

        # Check declared functions
        if claimed_funcs:
            for fn in claimed_funcs:
                if fn.lower() in declared_funcs:
                    return "supported", f"Function '{fn}' verified in {matched_key}."
                elif fn.lower() in content:
                    return "supported", f"Symbol '{fn}' referenced in {matched_key}."
                else:
                    return "unsupported", f"Function '{fn}' not found in {matched_key}."

        # Semantic check: Extract technical keywords from statement
        words = [w for w in re.findall(r"[a-z_]{4,}", statement) if w not in STOP_WORDS and w not in norm_path.lower()]
        if words:
            matches = [w for w in words if w in content]
            match_ratio = len(matches) / len(words)
            if match_ratio >= 0.4:
                return "supported", f"Verified in {matched_key} (Matched: {', '.join(matches[:3])})."
            else:
                return "hallucination", f"File '{matched_key}' exists, but claimed details ({', '.join(words[:3])}) are absent."

        return "supported", f"File '{matched_key}' verified in codebase."

    # If only functions are claimed without file
    if claimed_funcs:
        for path, info in files.items():
            func_names = [f["name"].lower() for f in info.get("functions", [])]
            for fn in claimed_funcs:
                if fn.lower() in func_names:
                    return "supported", f"Symbol '{fn}' found defined in {path}."
        return "unsupported", f"Symbol(s) {claimed_funcs} not declared in any scanned file."

    return "supported", "Ground truth confirmed."


def _verify_historical_claim(claim: dict[str, Any], commits: list[dict[str, Any]] | None) -> tuple[str, str]:
    """Verifies historical/commit claims against actual git commits."""
    if not commits:
        return "unsupported", "Historical commit record unavailable for verification."

    text = claim["statement"].lower()
    for c in commits:
        msg = (c.get("message") or "").lower()
        author = (c.get("author") or "").lower()
        sha = (c.get("sha") or "").lower()[:8]
        if (sha and sha in text) or (author and author in text) or any(w in msg for w in re.findall(r"[a-z_]{4,}", text) if w not in STOP_WORDS):
            return "supported", f"Historical match in commit {sha}: '{c.get('message')}'."

    return "unsupported", "No matching commit record supports this historical claim."


def evaluate_accuracy(
    question: str,
    answer: str,
    graph: dict[str, Any],
    commits: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    files = graph.get("files", {})
    claims = _extract_claims(answer)

    supported_claims = []
    unsupported_claims = []
    hallucinations = []
    missing_info = []

    total_weight = 0.0
    earned_weight = 0.0

    for c in claims:
        if c["category"] == "historical_claim":
            status, evidence = _verify_historical_claim(c, commits)
        else:
            status, evidence = _verify_code_claim(c, files)

        c["status"] = status
        c["evidence"] = evidence
        weight = c["confidence_weight"]
        total_weight += weight

        if status == "supported":
            earned_weight += weight
            supported_claims.append(c)
        elif status == "hallucination":
            hallucinations.append(c)
        elif status == "unsupported":
            unsupported_claims.append(c)
        else:
            earned_weight += (weight * 0.7)
            supported_claims.append(c)

    # Missing information detection
    q_terms = [t for t in re.findall(r"[a-z0-9_]{3,}", question.lower()) if t not in STOP_WORDS]
    repo_vocab = " ".join(files.keys()).lower()
    missing = [t for t in q_terms if t not in repo_vocab]
    if missing and len(missing) >= len(q_terms) * 0.5:
        missing_info.append(f"Repository context lacks concepts: {', '.join(missing[:4])}.")

    # Score calculation
    base_ratio = (earned_weight / total_weight) if total_weight > 0 else 0.5
    penalty = (len(hallucinations) * 0.3) + (len(unsupported_claims) * 0.12)
    confidence = max(5.0, min(99.0, (base_ratio - penalty) * 100))
    confidence_score = round(confidence, 1)

    verdict = "HIGH_CONFIDENCE" if confidence_score >= 80 else "MEDIUM_CONFIDENCE" if confidence_score >= 55 else "NEEDS_REVIEW"
    summary = (
        "Answer is thoroughly grounded in verified repository symbols." if verdict == "HIGH_CONFIDENCE"
        else "Answer contains grounded claims but relies on unverified assertions." if verdict == "MEDIUM_CONFIDENCE"
        else "Low confidence: Detected potential code hallucinations or unverified claims."
    )

    # Self-Correction refinement suggestion (Roadmap 4.1)
    refinement_prompt = None
    if verdict == "NEEDS_REVIEW" or hallucinations:
        refinement_prompt = (
            f"Your previous explanation contained unverified claims: "
            f"{[h['statement'] for h in hallucinations[:2]]}. "
            f"Please revise your answer relying ONLY on verified code files: {list(files.keys())[:5]}."
        )

    return {
        "confidence_score": confidence_score,
        "verdict": verdict,
        "summary": summary,
        "total_claims": len(claims),
        "supported_claims": supported_claims,
        "unsupported_claims": unsupported_claims,
        "hallucinations": hallucinations,
        "missing_information": missing_info,
        "refinement_prompt": refinement_prompt,
        "methodology": "AST symbol extraction, semantic keyword presence & commit verification (Feature 4.1)."
    }
