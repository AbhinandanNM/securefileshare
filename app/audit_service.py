from flask import request
from app import db
from app.models import SecurityAuditLog


def log_security_event(event_type: str, status: str, details: str, username: str = None, user_id: int = None, file_id: int = None, filename: str = None):
    """Log an immutable security audit event into the database."""
    try:
        ip = request.remote_addr if request else '127.0.0.1'
    except Exception:
        ip = '127.0.0.1'

    log_entry = SecurityAuditLog(
        event_type=event_type,
        status=status,
        username=username,
        user_id=user_id,
        file_id=file_id,
        filename=filename,
        ip_address=ip,
        details=details
    )
    try:
        db.session.add(log_entry)
        db.session.commit()
    except Exception:
        db.session.rollback()
