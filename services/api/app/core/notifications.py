from email.message import EmailMessage
from smtplib import SMTPException

import aiosmtplib

from app.core.config import settings


async def send_email(subject: str, body: str, to_email: str | None = None) -> dict[str, str]:
    recipient = to_email or str(settings.security_notification_to)
    if not settings.smtp_host:
        return {
            "status": "not_configured",
            "recipient": recipient,
            "detail": "SMTP_HOST is not configured; notification was recorded but not sent.",
        }

    message = EmailMessage()
    message["From"] = str(settings.smtp_from)
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=settings.smtp_starttls,
        )
    except (SMTPException, aiosmtplib.SMTPException, OSError) as exc:
        return {
            "status": "failed",
            "recipient": recipient,
            "detail": f"SMTP delivery failed: {exc}",
        }
    return {"status": "sent", "recipient": recipient, "detail": "Email notification sent."}
