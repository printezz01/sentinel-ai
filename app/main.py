"""
Sentinel AI — FastAPI Main Application
Run: uvicorn app.main:app --reload
"""

import asyncio
import logging

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.config import CORS_ORIGINS
from app.db import (
    new_uuid, create_scan_session, get_scan_session,
    get_findings, get_risk_score,
)
from app.engine import (
    get_chain_graph, calculate_risk_score, map_owasp_findings,
    search_rag, generate_remediation, OWASP_CATEGORIES,
)
from app.reporting import generate_pdf
from app.agent import run_agent
from app.scheduler import start_scheduler, stop_scheduler, add_subscription, remove_subscription, list_subscriptions

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinel.main")

# ─── App ──────────────────────────────────────────────────────
app = FastAPI(
    title="Sentinel AI",
    description="Autonomous Multi-Layer Security Intelligence Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app|http://localhost:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Start the APScheduler on app startup."""
    start_scheduler()
    logger.info("Sentinel AI started. Scheduler active.")


@app.on_event("shutdown")
async def shutdown_event():
    """Gracefully stop the scheduler."""
    stop_scheduler()


# ══════════════════════════════════════════════════════════════
# Target Validation (HARD CONSTRAINT)
# ══════════════════════════════════════════════════════════════

from app.validation import validate_target
from app.errors import ScanErrorException, UNKNOWN_ERROR


# ══════════════════════════════════════════════════════════════
# Request / Response Models
# ══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    target_type: str  # ip | subnet | url | github


class ChatRequest(BaseModel):
    question: str


# ══════════════════════════════════════════════════════════════
# Background scan runner
# ══════════════════════════════════════════════════════════════

async def _run_scan_background(scan_id: str, target: str, target_type: str):
    """Run the agent scan in background and email the PDF report upon completion."""
    try:
        await run_agent(scan_id, target, target_type)
        session = get_scan_session(scan_id)
        if session and session.get("status") == "complete":
            try:
                pdf_bytes = await asyncio.to_thread(generate_pdf, scan_id, target, session)
                findings = get_findings(scan_id)
                risk_data = calculate_risk_score(scan_id)
                risk_score = risk_data.get("score", 50) if isinstance(risk_data, dict) else 50
                from app.email_sender import send_report_email
                await asyncio.to_thread(
                    send_report_email,
                    pdf_bytes=pdf_bytes,
                    scan_id=scan_id,
                    target=target,
                    findings_count=len(findings),
                    risk_score=risk_score,
                )
            except Exception as mail_err:
                logger.error(f"Failed to email scan report for {scan_id}: {mail_err}")
    except ScanErrorException as e:
        logger.error(f"Background scan blocked: {e.scan_error.title}")
        from app.db import update_scan_status
        update_scan_status(scan_id, "failed", None, error_info=e.scan_error.to_dict())
    except Exception as e:
        logger.error(f"Background scan failed: {e}")
        from app.db import update_scan_status
        update_scan_status(scan_id, "failed", None, error_info=UNKNOWN_ERROR.to_dict())


# ══════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new scan session.
    Validates target format and network policy, creates session, starts async scan.
    Returns structured error JSON if validation fails.
    """
    target = req.target.strip()
    if req.target_type == "github" and not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    try:
        validate_target(target, req.target_type)
    except ScanErrorException as e:
        raise HTTPException(
            status_code=400,
            detail=e.scan_error.to_dict(),
        )

    scan_id = new_uuid()
    create_scan_session(scan_id, target, req.target_type)
    background_tasks.add_task(_run_scan_background, scan_id, target, req.target_type)

    logger.info(f"Scan {scan_id} started for {target} ({req.target_type})")
    return {"scan_id": scan_id}


@app.get("/scan/{scan_id}/status")
def scan_status(scan_id: str):
    """
    Get scan status — polled by frontend every 1-2 seconds.
    Returns current status, active tool, partial findings,
    and structured error info when the scan fails.
    """
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = get_findings(scan_id)
    partial = [
        {
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "layer": f.get("layer"),
            "cve_id": f.get("cve_id"),
        }
        for f in findings
    ]

    response: dict = {
        "status": session.get("status", "unknown"),
        "current_tool": session.get("current_tool"),
        "findings_so_far": partial,
    }

    # Attach structured error info if the scan failed
    if session.get("error_info"):
        response["error_info"] = session["error_info"]

    # Attach per-tool warnings for partial scans
    if session.get("tool_warnings"):
        response["tool_warnings"] = session["tool_warnings"]

    return response


@app.get("/scan/{scan_id}/dashboard")
def scan_dashboard(scan_id: str):
    """
    Get full dashboard data including severity breakdown, findings,
    risk score, and OWASP mapping.
    """
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = get_findings(scan_id)

    # Severity breakdown
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    # Risk score
    risk = get_risk_score(scan_id)
    risk_score = risk["score"] if risk else 0

    # OWASP mapping
    owasp = map_owasp_findings(scan_id)

    return {
        "status": session.get("status", "unknown"),
        "severity_breakdown": severity_breakdown,
        "findings": findings,
        "risk_score": risk_score,
        "owasp_mapping": owasp,
    }


@app.get("/scan/{scan_id}/chain")
def scan_chain(scan_id: str):
    """Get attack chain as Cytoscape.js-compatible JSON graph."""
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return get_chain_graph(scan_id)


@app.post("/scan/{scan_id}/chat")
def scan_chat(scan_id: str, req: ChatRequest):
    """
    RAG-powered chat about scan findings.
    Uses Gemini (free) → Claude (paid) → keyword fallback.
    """
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = search_rag(scan_id, req.question)

    # Build context text for LLM
    context_text = "\n".join(
        f"- [{c.get('severity', 'info').upper()}] {c.get('title', '')}: {c.get('description', '')}"
        for c in context
    )
    prompt = f"""Based on these security findings, answer the question.

Findings:
{context_text}

Question: {req.question}

Provide a clear, actionable answer."""

    answer = ""

    # Try 1: Groq (FREE, fastest)
    from app.config import GROQ_API_KEY, GOOGLE_API_KEY, ANTHROPIC_API_KEY
    if GROQ_API_KEY and not answer:
        try:
            from groq import Groq
            from app.config import GROQ_MODEL
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
            )
            answer = response.choices[0].message.content
            logger.info("Chat answered via Groq (free)")
        except Exception as e:
            logger.warning(f"Groq chat failed: {e}")

    # Try 2: Gemini (FREE)
    if GOOGLE_API_KEY and not answer:
        try:
            import google.generativeai as genai
            from app.config import GEMINI_MODEL
            genai.configure(api_key=GOOGLE_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            response = model.generate_content(prompt)
            answer = response.text
            logger.info("Chat answered via Gemini (free)")
        except Exception as e:
            logger.warning(f"Gemini chat failed: {e}")

    # Try 2: Claude (PAID)
    if ANTHROPIC_API_KEY and not answer:
        try:
            import anthropic
            from app.config import CLAUDE_PRIMARY_MODEL, CLAUDE_FALLBACK_MODEL
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            try:
                response = client.messages.create(
                    model=CLAUDE_PRIMARY_MODEL, max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                response = client.messages.create(
                    model=CLAUDE_FALLBACK_MODEL, max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}],
                )
            answer = response.content[0].text
            logger.info("Chat answered via Claude (paid)")
        except Exception as e:
            logger.warning(f"Claude chat failed: {e}")

    # Try 3: Demo fallback (no LLM)
    if not answer:
        if context:
            summary_lines = []
            for c in context[:5]:
                sev = c.get("severity", "info").upper()
                summary_lines.append(f"• [{sev}] {c.get('title', 'Unknown')}: {c.get('description', '')[:120]}")
            answer = f"Based on {len(context)} relevant findings for your query:\n\n" + "\n".join(summary_lines)
        else:
            answer = "No relevant findings matched your query. Try asking about specific vulnerabilities, CVEs, or security layers."

    return {
        "answer": answer,
        "context": context[:5],
    }


@app.get("/scan/{scan_id}/report")
def scan_report(scan_id: str):
    """Generate and download PDF security report."""
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    if session.get("status") != "complete":
        raise HTTPException(status_code=409, detail="Report requires a completed scan")

    try:
        pdf_bytes = generate_pdf(scan_id, session.get("target", "Unknown"), session)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed") from e

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="sentinel_report_{scan_id}.pdf"',
        },
    )


# ══════════════════════════════════════════════════════════════
# Subscription & Scheduled Scan Endpoints
# ══════════════════════════════════════════════════════════════

class SubscribeRequest(BaseModel):
    target: str
    target_type: str   # ip | subnet | url | github
    email: str = "printezz01@gmail.com"
    interval_minutes: int = Field(default=5, ge=1, le=10080)


@app.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    """
    Register a target for automated periodic scanning.
    The AI agent will scan the target every `interval_minutes` minutes
    and email a full PDF report to the specified email address.
    """
    try:
        validate_target(req.target, req.target_type)
    except ScanErrorException as e:
        raise HTTPException(
            status_code=400,
            detail=e.scan_error.to_dict(),
        )
    sub_id = new_uuid()

    add_subscription(
        sub_id=sub_id,
        target=req.target,
        target_type=req.target_type,
        email=req.email,
        interval_minutes=req.interval_minutes,
    )

    logger.info(f"New subscription {sub_id} registered for {req.target} → {req.email}")
    return {
        "sub_id": sub_id,
        "message": f"Subscribed! Scanning '{req.target}' every {req.interval_minutes} minutes. Reports will be emailed to {req.email}.",
        "target": req.target,
        "email": req.email,
        "interval_minutes": req.interval_minutes,
    }


@app.delete("/subscribe/{sub_id}")
async def unsubscribe(sub_id: str):
    """Cancel a scheduled scan subscription."""
    remove_subscription(sub_id)
    return {"message": f"Subscription {sub_id} cancelled."}


@app.get("/subscriptions")
async def get_subscriptions():
    """List all active scan subscriptions."""
    return {"subscriptions": list_subscriptions()}
