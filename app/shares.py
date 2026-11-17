from datetime import datetime, timezone
from flask import Blueprint, jsonify, request

from app import db
from app.audit_service import log_security_event
from app.middleware import token_required
from app.models import File, FileShare, User

shares_bp = Blueprint('shares', __name__, url_prefix='/api/shares')


# ---------------------------------------------------------------------------
# POST /api/shares/
# ---------------------------------------------------------------------------
@shares_bp.route('/', methods=['POST'])
@token_required
def create_share(current_user_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    data = request.get_json(silent=True) or {}

    file_id = data.get('file_id')
    shared_with_username = (data.get('shared_with_username') or '').strip()
    permission = (data.get('permission') or 'read').strip().lower()
    expires_at_str = data.get('expires_at')

    if not file_id or not shared_with_username:
        return jsonify({
            'status': 'error',
            'message': 'file_id and shared_with_username are required',
            'data': {},
        }), 400

    if permission not in ('read', 'write'):
        return jsonify({
            'status': 'error',
            'message': "permission must be 'read' or 'write'",
            'data': {},
        }), 400

    file_record = File.query.get(file_id)
    if not file_record:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    if file_record.owner_id != current_user_id:
        return jsonify({'status': 'error', 'message': 'Only the file owner can grant share permissions'}), 403

    target_user = User.query.filter_by(username=shared_with_username).first()
    if not target_user:
        return jsonify({'status': 'error', 'message': f"User '{shared_with_username}' does not exist"}), 404

    if target_user.id == current_user_id:
        return jsonify({'status': 'error', 'message': 'Cannot share a file with yourself'}), 400

    # Parse optional expiry date
    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'expires_at must be an ISO date string (YYYY-MM-DD)'}), 400

    # Check if active share already exists; update it if so
    existing = FileShare.query.filter_by(file_id=file_id, shared_with=target_user.id).first()
    if existing:
        existing.permission = permission
        existing.expires_at = expires_at
        existing.revoked = False
        share = existing
    else:
        share = FileShare(
            file_id=file_id,
            shared_by=current_user_id,
            shared_with=target_user.id,
            permission=permission,
            expires_at=expires_at,
        )
        db.session.add(share)

    db.session.commit()

    log_security_event(
        event_type='FILE_SHARED',
        status='SUCCESS',
        details=f"Owner '{username}' granted {permission.upper()} access on '{file_record.filename}' to '{shared_with_username}'" + (f" (expires {expires_at_str})" if expires_at_str else " (no expiry)"),
        username=username,
        user_id=current_user_id,
        file_id=file_id,
        filename=file_record.filename,
    )

    return jsonify({
        'status': 'success',
        'message': f"Access granted to '{shared_with_username}' with '{permission}' permission",
        'data': share.to_dict(),
    }), 201


# ---------------------------------------------------------------------------
# GET /api/shares/
# ---------------------------------------------------------------------------
@shares_bp.route('/', methods=['GET'])
@token_required
def list_shares(current_user_id):
    now = datetime.now(timezone.utc)
    created = FileShare.query.filter_by(shared_by=current_user_id).all()
    received = FileShare.query.filter_by(shared_with=current_user_id, revoked=False).all()

    # Filter out expired received shares or flag them
    received_list = []
    for s in received:
        d = s.to_dict()
        is_expired = False
        if s.expires_at and s.expires_at.replace(tzinfo=timezone.utc) < now:
            is_expired = True
        d['is_expired'] = is_expired
        received_list.append(d)

    return jsonify({
        'status': 'success',
        'message': 'Shares retrieved',
        'data': {
            'shares_created': [s.to_dict() for s in created],
            'shares_received': received_list,
        },
    }), 200


# ---------------------------------------------------------------------------
# DELETE /api/shares/<int:id> — Revoke Access (Objective O5)
# ---------------------------------------------------------------------------
@shares_bp.route('/<int:share_id>', methods=['DELETE'])
@token_required
def revoke_share(current_user_id, share_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    share = FileShare.query.get(share_id)
    if not share:
        return jsonify({'status': 'error', 'message': 'Share record not found'}), 404

    if share.shared_by != current_user_id:
        return jsonify({'status': 'error', 'message': 'Only the owner who shared this file can revoke access'}), 403

    recipient_name = share.recipient.username if share.recipient else 'Unknown'
    filename = share.file.filename if share.file else 'Unknown'

    share.revoked = True
    db.session.commit()

    log_security_event(
        event_type='SHARE_REVOKED',
        status='SUCCESS',
        details=f"Owner '{username}' REVOKED access for '{recipient_name}' to file '{filename}'",
        username=username,
        user_id=current_user_id,
        file_id=share.file_id,
        filename=filename,
    )

    return jsonify({
        'status': 'success',
        'message': f"Access revoked for '{recipient_name}'. User can no longer decrypt or download '{filename}'",
        'data': share.to_dict(),
    }), 200
