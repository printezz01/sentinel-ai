"""
Sentinel AI — Scan History & Comparison Logic
"""

from typing import Dict, Any, List
from app.db import (
    get_scan_session,
    get_scan_sessions_by_target,
    get_findings,
    get_chain_edge_count,
    get_risk_score
)

def normalize_target(target: str) -> str:
    """Normalize a target string to ensure consistent matching."""
    if not target:
        return target
    # Strip trailing slashes and convert to lowercase
    return target.strip().rstrip('/').lower()


def compare_scans(latest_scan_id: str, previous_scan_id: str) -> Dict[str, Any]:
    """
    Compare findings between the latest scan and the previous scan.
    Returns categorized findings: NEW, RESOLVED, UNCHANGED.
    """
    latest_findings = get_findings(latest_scan_id)
    previous_findings = get_findings(previous_scan_id)
    
    # We use a stable identifier for matching findings: normalized title + layer
    def make_key(finding: dict) -> str:
        title = (finding.get("title") or "").strip().lower()
        layer = (finding.get("layer") or "").strip().lower()
        return f"{title}::{layer}"
    
    prev_map = {make_key(f): f for f in previous_findings}
    latest_map = {make_key(f): f for f in latest_findings}
    
    new_findings = []
    unchanged_findings = []
    resolved_findings = []
    
    for key, f in latest_map.items():
        if key in prev_map:
            unchanged_findings.append(f)
        else:
            new_findings.append(f)
            
    for key, f in prev_map.items():
        if key not in latest_map:
            resolved_findings.append(f)
            
    # Calculate status summary
    if not new_findings and not resolved_findings:
        status_summary = "No security change detected"
    elif resolved_findings and not new_findings:
        status_summary = "Security posture improved"
    elif new_findings and not resolved_findings:
        status_summary = "New security issues detected"
    else:
        status_summary = "Security posture changed"

    return {
        "summary": status_summary,
        "counts": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "unchanged": len(unchanged_findings)
        },
        "findings": {
            "new": new_findings,
            "resolved": resolved_findings,
            "unchanged": unchanged_findings
        }
    }


def get_scan_history_for_session(scan_id: str) -> Dict[str, Any]:
    """
    Retrieves the scan history for the target associated with the given scan_id.
    Performs comparison if there is a previous scan.
    """
    session = get_scan_session(scan_id)
    if not session:
        return {"error": "Scan not found"}
        
    target = session.get("target")
    if not target:
        return {"error": "Target not found for scan"}
        
    normalized_target = normalize_target(target)
    
    # Fetch all completed scans. Since get_scan_sessions_by_target does exact match,
    # we can also fetch all scans and filter by normalized target to be safe.
    from app.db import get_all_scan_sessions
    all_scans = get_all_scan_sessions()
    
    target_scans = [
        s for s in all_scans 
        if normalize_target(s.get("target", "")) == normalized_target
    ]
    
    # Ensure they are sorted by created_at desc (get_all_scan_sessions does this, but let's be sure)
    target_scans.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    
    if len(target_scans) <= 1:
        # First scan or only this scan exists
        latest_scan = target_scans[0] if target_scans else session
        
        # We need stats for the latest scan
        latest_findings = get_findings(latest_scan["id"])
        critical_count = sum(1 for f in latest_findings if f.get("severity") == "critical")
        risk_data = get_risk_score(latest_scan["id"])
        
        return {
            "target": target,
            "history_available": False,
            "message": "First scan recorded",
            "latest_scan": {
                "id": latest_scan["id"],
                "created_at": latest_scan.get("created_at"),
                "total_findings": len(latest_findings),
                "critical_findings": critical_count,
                "attack_paths": get_chain_edge_count(latest_scan["id"]),
                "risk_score": risk_data.get("score", 0) if risk_data else 0
            },
            "previous_scans": []
        }
        
    # We have multiple scans. 
    # Current scan might be the latest completed one, or maybe it's still running.
    # We compare the two most recent completed scans for this target.
    latest = target_scans[0]
    previous = target_scans[1]
    
    comparison = compare_scans(latest["id"], previous["id"])
    
    latest_findings = get_findings(latest["id"])
    latest_critical = sum(1 for f in latest_findings if f.get("severity") == "critical")
    latest_risk = get_risk_score(latest["id"])
    
    previous_findings = get_findings(previous["id"])
    previous_critical = sum(1 for f in previous_findings if f.get("severity") == "critical")
    previous_risk = get_risk_score(previous["id"])
    
    # Attack paths summary text
    latest_paths = get_chain_edge_count(latest["id"])
    prev_paths = get_chain_edge_count(previous["id"])
    
    if latest_paths == 0 and prev_paths > 0:
        path_summary = "Attack path eliminated"
    elif latest_paths > 0 and prev_paths == 0:
        path_summary = "New attack path detected"
    elif latest_paths != prev_paths:
        path_summary = "Attack paths changed"
    else:
        path_summary = "No change in attack paths"
        
    comparison["path_summary"] = path_summary
    
    older_scans = []
    if len(target_scans) > 2:
        for s in target_scans[2:]:
            s_findings = get_findings(s["id"])
            older_scans.append({
                "id": s["id"],
                "created_at": s.get("created_at"),
                "total_findings": len(s_findings)
            })

    return {
        "target": target,
        "history_available": True,
        "comparison": comparison,
        "latest_scan": {
            "id": latest["id"],
            "created_at": latest.get("created_at"),
            "total_findings": len(latest_findings),
            "critical_findings": latest_critical,
            "attack_paths": latest_paths,
            "risk_score": latest_risk.get("score", 0) if latest_risk else 0
        },
        "previous_scan": {
            "id": previous["id"],
            "created_at": previous.get("created_at"),
            "total_findings": len(previous_findings),
            "critical_findings": previous_critical,
            "attack_paths": prev_paths,
            "risk_score": previous_risk.get("score", 0) if previous_risk else 0
        },
        "older_scans": older_scans
    }
