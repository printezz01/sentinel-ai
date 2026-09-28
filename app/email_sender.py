"""
Sentinel AI — Email Reporter
Sends the PDF scan report to a Gmail address via SMTP.
"""
import smtplib
import logging
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from app.config import SMTP_USER, SMTP_PASS, REPORT_EMAIL

logger = logging.getLogger("sentinel.email")


def send_report_email(pdf_bytes: bytes, scan_id: str, target: str, findings_count: int, risk_score: int, recipient: str | None = None) -> bool:
    """
    Send the security scan PDF report to the configured email address.

    Args:
        pdf_bytes: Raw bytes of the generated PDF report.
        scan_id: The UUID of the completed scan.
        target: The scanned target (GitHub URL, IP, etc).
        findings_count: Total number of vulnerabilities found.
        risk_score: The calculated risk score (0-100).

    Returns:
        True if email sent successfully, False otherwise.
    """
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP credentials not configured. Skipping email report.")
        return False

    recipient = recipient or REPORT_EMAIL or SMTP_USER
    severity_label = "CRITICAL" if risk_score < 30 else "HIGH" if risk_score < 60 else "MEDIUM" if risk_score < 80 else "LOW"

    try:
        msg = EmailMessage()
        msg["Subject"] = f"🔐 Sentinel AI — Daily Security Report | Risk: {severity_label} ({risk_score}/100)"
        msg["From"] = f"Sentinel AI <{SMTP_USER}>"
        msg["To"] = recipient
        msg["Date"] = formatdate(localtime=True)

        # Plain text fallback
        msg.set_content(f"""
Sentinel AI — Automated Security Report
========================================

Target:        {target}
Risk Score:    {risk_score}/100 ({severity_label})
Vulnerabilities: {findings_count} findings
Scan ID:       {scan_id}

Please see the attached PDF for the full detailed report with
remediation steps and attack chain analysis.

—
Sentinel AI Autonomous Security Engine
This is an automated report sent every 5 minutes.
        """.strip())

        # HTML body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background: #0f1108; color: #d4d7c4; margin: 0; padding: 0;">
            <div style="max-width: 600px; margin: 40px auto; background: #1a1d14; border: 1px solid #2e3226; border-radius: 12px; overflow: hidden;">
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #1a2e0f, #2a3d1a); padding: 32px 40px; border-bottom: 1px solid #2e3226;">
                    <h1 style="margin: 0; color: #7bc96f; font-size: 22px; letter-spacing: 0.05em;">🔐 Sentinel AI</h1>
                    <p style="margin: 4px 0 0; color: #8a8e7c; font-size: 13px;">Automated Daily Security Report</p>
                </div>
                <!-- Risk Score -->
                <div style="padding: 32px 40px; text-align: center; border-bottom: 1px solid #2e3226;">
                    <div style="display: inline-block; background: {'#3d1414' if risk_score < 30 else '#3d2814' if risk_score < 60 else '#3d3414' if risk_score < 80 else '#1a2e0f'}; border: 1px solid {'#c75050' if risk_score < 30 else '#d4784a' if risk_score < 60 else '#c4a644' if risk_score < 80 else '#7a9c5e'}; border-radius: 12px; padding: 20px 40px;">
                        <div style="font-size: 52px; font-weight: bold; color: {'#c75050' if risk_score < 30 else '#d4784a' if risk_score < 60 else '#c4a644' if risk_score < 80 else '#7a9c5e'}; font-family: monospace;">{risk_score}</div>
                        <div style="font-size: 11px; letter-spacing: 0.2em; color: #8a8e7c; margin-top: 4px;">RISK SCORE / 100</div>
                    </div>
                </div>
                <!-- Details -->
                <div style="padding: 32px 40px; border-bottom: 1px solid #2e3226;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 10px 0; color: #8a8e7c; font-size: 13px;">Target Scanned</td>
                            <td style="padding: 10px 0; color: #d4d7c4; font-size: 13px; font-family: monospace;">{target}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #8a8e7c; font-size: 13px;">Vulnerabilities Found</td>
                            <td style="padding: 10px 0; color: #d4d7c4; font-size: 13px; font-weight: bold;">{findings_count} findings detected</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #8a8e7c; font-size: 13px;">Threat Level</td>
                            <td style="padding: 10px 0; font-size: 13px; font-weight: bold; color: {'#c75050' if risk_score < 30 else '#d4784a' if risk_score < 60 else '#c4a644' if risk_score < 80 else '#7a9c5e'};">{severity_label}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #8a8e7c; font-size: 13px;">Scan ID</td>
                            <td style="padding: 10px 0; color: #8a8e7c; font-size: 11px; font-family: monospace;">{scan_id}</td>
                        </tr>
                    </table>
                </div>
                <!-- Footer -->
                <div style="padding: 24px 40px; text-align: center;">
                    <p style="color: #8a8e7c; font-size: 12px; margin: 0;">
                        📎 Your full PDF report with remediation steps and attack chain analysis is attached.<br>
                        <span style="color: #4a4e3e;">Powered by Sentinel AI · Groq · Voyage AI · LangGraph</span>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        msg.add_alternative(html_body, subtype="html")

        # Attach PDF
        msg.add_attachment(
            pdf_bytes,
            maintype="application",
            subtype="pdf",
            filename=f"sentinel_report_{scan_id[:8]}.pdf"
        )

        # Send via Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)

        logger.info(f"✅ Security report emailed to {recipient} for scan {scan_id}")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to send email report: {e}")
        return False
