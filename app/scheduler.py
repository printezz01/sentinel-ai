"""
Sentinel AI — Scheduler
Runs autonomous daily security scans and emails the PDF report.
Uses APScheduler to run every 5 minutes for demo purposes.
"""
import logging
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger("sentinel.scheduler")

# APScheduler instance (initialized once)
scheduler = AsyncIOScheduler()

# In-memory subscription registry
# Format: { "sub_id": { "target": str, "target_type": str, "email": str } }
_subscriptions: dict[str, dict] = {}


async def _run_scheduled_scan(sub_id: str, target: str, target_type: str, email: str):
    """
    Runs a full scan + generates PDF + emails the report.
    Triggered by APScheduler every 5 minutes.
    """
    import uuid
    from app.db import create_scan_session, get_scan_session
    from app.agent import run_agent
    from app.engine import calculate_risk_score
    from app.reporting import generate_pdf
    from app.db import get_findings
    from app.email_sender import send_report_email

    scan_id = str(uuid.uuid4())
    logger.info(f"[SCHEDULER] Starting scheduled scan {scan_id} for {target} (sub: {sub_id})")

    try:
        # 1. Create a new scan session
        create_scan_session(scan_id, target, target_type)

        # 2. Run the full AI agent scan
        await run_agent(scan_id, target, target_type)

        # 3. Generate the PDF report
        session = get_scan_session(scan_id)
        pdf_bytes = generate_pdf(scan_id, target, session)

        # 4. Get stats for the email body
        findings = get_findings(scan_id)
        risk_data = calculate_risk_score(scan_id)
        risk_score = risk_data.get("score", 50) if isinstance(risk_data, dict) else 50

        # 5. Send the email with PDF attached
        sent = send_report_email(
            pdf_bytes=pdf_bytes,
            scan_id=scan_id,
            target=target,
            findings_count=len(findings),
            risk_score=risk_score
        )

        if sent:
            logger.info(f"[SCHEDULER] ✅ Report emailed to {email} for scan {scan_id}")
        else:
            logger.warning(f"[SCHEDULER] ⚠️ Scan {scan_id} complete but email not sent (check SMTP config)")

    except Exception as e:
        logger.error(f"[SCHEDULER] ❌ Scheduled scan failed for {target}: {e}")


def add_subscription(sub_id: str, target: str, target_type: str, email: str, interval_minutes: int = 5):
    """
    Register a new subscription to receive periodic scan reports.
    Adds an APScheduler job that fires every `interval_minutes` minutes.
    """
    if sub_id in _subscriptions:
        logger.info(f"[SCHEDULER] Subscription {sub_id} already exists. Skipping.")
        return

    _subscriptions[sub_id] = {
        "target": target,
        "target_type": target_type,
        "email": email,
        "interval_minutes": interval_minutes,
    }

    scheduler.add_job(
        func=_run_scheduled_scan,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id=sub_id,
        kwargs={
            "sub_id": sub_id,
            "target": target,
            "target_type": target_type,
            "email": email,
        },
        replace_existing=True,
        max_instances=1,  # Only one scan at a time per subscription
        misfire_grace_time=60,
    )
    logger.info(f"[SCHEDULER] ✅ Registered job {sub_id} — scanning '{target}' every {interval_minutes} minutes → {email}")


def remove_subscription(sub_id: str):
    """Cancel a scheduled scan subscription."""
    if sub_id in _subscriptions:
        del _subscriptions[sub_id]
    try:
        scheduler.remove_job(sub_id)
        logger.info(f"[SCHEDULER] Removed subscription {sub_id}")
    except Exception:
        pass


def list_subscriptions() -> list[dict]:
    """Return all active subscriptions."""
    return [{"sub_id": k, **v} for k, v in _subscriptions.items()]


def start_scheduler():
    """Start the APScheduler. Called on FastAPI startup."""
    if not scheduler.running:
        scheduler.start()
        logger.info("[SCHEDULER] APScheduler started ✅")


def stop_scheduler():
    """Gracefully stop the scheduler. Called on FastAPI shutdown."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("[SCHEDULER] APScheduler stopped")
