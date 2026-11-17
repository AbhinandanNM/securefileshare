import hashlib
import io
import os
import uuid
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from app import db
from app.audit_service import log_security_event
from app.crypto_utils import (
    compute_hash,
    decrypt_file,
    derive_master_key,
    encrypt_file,
    format_hex_dump,
    verify_hash,
)
from app.middleware import token_required
from app.models import File, FileShare, User

files_bp = Blueprint('files', __name__, url_prefix='/api/files')


def _get_master_key() -> bytes:
    """Retrieve application Master Key derived with PBKDF2."""
    secret = current_app.config['SECRET_KEY']
    return derive_master_key(secret)


# ---------------------------------------------------------------------------
# POST /api/files/upload
# ---------------------------------------------------------------------------
@files_bp.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    if 'file' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file part in request',
            'data': {},
        }), 400

    uploaded = request.files['file']
    if uploaded.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No file selected',
            'data': {},
        }), 400

    original_name = secure_filename(uploaded.filename)
    plaintext = uploaded.read()

    if len(plaintext) == 0:
        return jsonify({
            'status': 'error',
            'message': 'Empty files are not allowed',
            'data': {},
        }), 400

    # 1. Objective O3: Compute pre-storage SHA-256 integrity hash
    plaintext_hash = compute_hash(plaintext)

    # 2. Objective O2: Encrypt with AES-256-CBC (per-file DEK wrapped with KEK)
    master_key = _get_master_key()
    crypto_res = encrypt_file(plaintext, master_key)

    # 3. Persist encrypted ciphertext to uploads/<uuid>
    stored_name = str(uuid.uuid4())
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, stored_name)

    with open(file_path, 'wb') as fh:
        fh.write(crypto_res['ciphertext'])

    # Also keep a backup copy for the live tamper simulation demo
    backup_path = file_path + '.orig'
    with open(backup_path, 'wb') as fh:
        fh.write(crypto_res['ciphertext'])

    # 4. Save file metadata
    file_record = File(
        owner_id=current_user_id,
        filename=original_name,
        stored_name=stored_name,
        file_hash=plaintext_hash,
        ciphertext_hash=crypto_res['ciphertext_hash'],
        encrypted_key=crypto_res['encrypted_key'].hex(),
        iv=crypto_res['iv'].hex(),
        cipher_algo='AES-256-CBC',
        hash_algo='SHA-256',
        size=len(plaintext),
        ciphertext_size=len(crypto_res['ciphertext']),
        is_tampered=False,
    )
    db.session.add(file_record)
    db.session.commit()

    # Log audit event
    log_security_event(
        event_type='FILE_UPLOAD_ENCRYPT',
        status='SUCCESS',
        details=f"File '{original_name}' encrypted with AES-256-CBC (IV: {file_record.iv[:8]}...). SHA-256 digest: {plaintext_hash[:16]}...",
        username=username,
        user_id=current_user_id,
        file_id=file_record.id,
        filename=original_name,
    )

    return jsonify({
        'status': 'success',
        'message': f"File '{original_name}' encrypted with AES-256-CBC and stored securely",
        'data': file_record.to_dict(),
    }), 201


# ---------------------------------------------------------------------------
# GET /api/files/
# ---------------------------------------------------------------------------
@files_bp.route('/', methods=['GET'])
@token_required
def list_files(current_user_id):
    files = File.query.filter_by(owner_id=current_user_id).order_by(File.uploaded_at.desc()).all()
    return jsonify({
        'status': 'success',
        'message': 'Files retrieved',
        'data': {'files': [f.to_dict() for f in files]},
    }), 200


# ---------------------------------------------------------------------------
# GET /api/files/<int:id>/download
# ---------------------------------------------------------------------------
@files_bp.route('/<int:file_id>/download', methods=['GET'])
@token_required
def download_file(current_user_id, file_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    file_record = File.query.get(file_id)
    if not file_record:
        return jsonify({'status': 'error', 'message': 'File not found', 'data': {}}), 404

    # Access Control check (Objective O5)
    is_owner = (file_record.owner_id == current_user_id)
    if not is_owner:
        now = datetime.now(timezone.utc)
        share = FileShare.query.filter_by(
            file_id=file_id,
            shared_with=current_user_id,
            revoked=False,
        ).first()

        if not share:
            log_security_event(
                event_type='UNAUTHORIZED_ACCESS_BLOCKED',
                status='CRITICAL',
                details=f"User '{username}' attempted unauthorized download of file '{file_record.filename}'",
                username=username,
                user_id=current_user_id,
                file_id=file_id,
                filename=file_record.filename,
            )
            return jsonify({'status': 'error', 'message': 'Access denied: You do not have permission to access this file'}), 403

        if share.expires_at and share.expires_at.replace(tzinfo=timezone.utc) < now:
            log_security_event(
                event_type='UNAUTHORIZED_ACCESS_BLOCKED',
                status='WARNING',
                details=f"User '{username}' attempted download of expired shared file '{file_record.filename}'",
                username=username,
                user_id=current_user_id,
                file_id=file_id,
                filename=file_record.filename,
            )
            return jsonify({'status': 'error', 'message': 'Share permission for this file has expired'}), 403

    # Load ciphertext from disk
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file_record.stored_name)
    if not os.path.exists(file_path):
        return jsonify({'status': 'error', 'message': 'Encrypted file chunk missing on server'}), 404

    with open(file_path, 'rb') as fh:
        ciphertext = fh.read()

    # Decrypt per-file DEK using KEK, then decrypt ciphertext using AES-256-CBC
    master_key = _get_master_key()
    encrypted_key = bytes.fromhex(file_record.encrypted_key)
    iv = bytes.fromhex(file_record.iv)

    try:
        plaintext = decrypt_file(ciphertext, encrypted_key, iv, master_key)
    except Exception as e:
        log_security_event(
            event_type='DECRYPTION_FAILED',
            status='CRITICAL',
            details=f"Decryption failed for '{file_record.filename}' - Possible ciphertext corruption: {str(e)}",
            username=username,
            user_id=current_user_id,
            file_id=file_id,
            filename=file_record.filename,
        )
        return jsonify({
            'status': 'error',
            'message': 'Decryption failed: Ciphertext appears damaged or invalid padding',
            'data': {},
        }), 500

    # Objective O3: Mandatory Integrity Verification (Plaintext SHA-256 check)
    computed_hash = compute_hash(plaintext)
    if not verify_hash(plaintext, file_record.file_hash):
        log_security_event(
            event_type='INTEGRITY_CHECK_FAIL',
            status='CRITICAL',
            details=f"SECURITY ALERT! File '{file_record.filename}' has been tampered with! Expected SHA-256 {file_record.file_hash[:16]}..., got {computed_hash[:16]}...",
            username=username,
            user_id=current_user_id,
            file_id=file_id,
            filename=file_record.filename,
        )
        return jsonify({
            'status': 'error',
            'message': f'CRITICAL SECURITY ALERT: File integrity check failed! Expected hash {file_record.file_hash[:16]}... but computed {computed_hash[:16]}... File may have been tampered with.',
            'data': {'expected_hash': file_record.file_hash, 'computed_hash': computed_hash},
        }), 409

    log_security_event(
        event_type='FILE_DOWNLOAD_DECRYPT',
        status='SUCCESS',
        details=f"File '{file_record.filename}' verified (SHA-256 match) and decrypted successfully for user '{username}'",
        username=username,
        user_id=current_user_id,
        file_id=file_id,
        filename=file_record.filename,
    )

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_record.filename,
        mimetype='application/octet-stream',
    )


# ---------------------------------------------------------------------------
# GET /api/files/<int:id>/crypto-details (Inspector Endpoint)
# ---------------------------------------------------------------------------
@files_bp.route('/<int:file_id>/crypto-details', methods=['GET'])
@token_required
def get_crypto_details(current_user_id, file_id):
    file_record = File.query.get(file_id)
    if not file_record:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    # Allow owner or recipient
    is_authorized = (file_record.owner_id == current_user_id) or FileShare.query.filter_by(
        file_id=file_id, shared_with=current_user_id, revoked=False
    ).first()

    if not is_authorized:
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file_record.stored_name)
    ciphertext = b''
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            ciphertext = fh.read()

    hex_dump = format_hex_dump(ciphertext, max_bytes=128)

    # Perform a safe dry-run integrity check
    integrity_pass = False
    try:
        master_key = _get_master_key()
        pt = decrypt_file(ciphertext, bytes.fromhex(file_record.encrypted_key), bytes.fromhex(file_record.iv), master_key)
        integrity_pass = verify_hash(pt, file_record.file_hash)
    except Exception:
        integrity_pass = False

    return jsonify({
        'status': 'success',
        'data': {
            'file_id': file_record.id,
            'filename': file_record.filename,
            'cipher_algorithm': file_record.cipher_algo,
            'cipher_mode': 'CBC (Cipher Block Chaining)',
            'key_size_bits': 256,
            'block_size_bytes': 16,
            'padding_standard': 'PKCS#7',
            'hash_algorithm': file_record.hash_algo,
            'plaintext_sha256': file_record.file_hash,
            'ciphertext_sha256': file_record.ciphertext_hash or compute_hash(ciphertext),
            'iv_hex': file_record.iv,
            'wrapped_dek_hex': file_record.encrypted_key,
            'plaintext_size_bytes': file_record.size,
            'ciphertext_size_bytes': len(ciphertext),
            'ciphertext_hex_preview': hex_dump,
            'is_tampered': file_record.is_tampered,
            'integrity_status': 'VERIFIED' if integrity_pass else 'TAMPERED_OR_CORRUPT',
        }
    }), 200


# ---------------------------------------------------------------------------
# POST /api/files/<int:id>/verify-integrity (Live Academic Verification)
# ---------------------------------------------------------------------------
@files_bp.route('/<int:file_id>/verify-integrity', methods=['POST'])
@token_required
def verify_file_integrity(current_user_id, file_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    file_record = File.query.get(file_id)
    if not file_record:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file_record.stored_name)
    if not os.path.exists(file_path):
        return jsonify({'status': 'error', 'message': 'File chunk not found'}), 404

    with open(file_path, 'rb') as fh:
        ciphertext = fh.read()

    master_key = _get_master_key()
    try:
        plaintext = decrypt_file(ciphertext, bytes.fromhex(file_record.encrypted_key), bytes.fromhex(file_record.iv), master_key)
        computed_hash = compute_hash(plaintext)
        matches = (computed_hash == file_record.file_hash)
    except Exception as e:
        computed_hash = 'DECRYPTION_EXCEPTION'
        matches = False

    if matches:
        log_security_event(
            event_type='INTEGRITY_CHECK_PASS',
            status='SUCCESS',
            details=f"Live audit: SHA-256 integrity passed for '{file_record.filename}' ({computed_hash[:16]}...)",
            username=username,
            user_id=current_user_id,
            file_id=file_id,
            filename=file_record.filename,
        )
        return jsonify({
            'status': 'success',
            'data': {
                'passed': True,
                'expected_hash': file_record.file_hash,
                'computed_hash': computed_hash,
                'message': 'Integrity Verified: Plaintext hash matches stored SHA-256 digest exactly. Zero tampering detected.',
            }
        }), 200
    else:
        log_security_event(
            event_type='INTEGRITY_CHECK_FAIL',
            status='CRITICAL',
            details=f"Live audit: TAMPERING DETECTED for '{file_record.filename}'. Stored {file_record.file_hash[:16]}... vs Computed {computed_hash[:16]}...",
            username=username,
            user_id=current_user_id,
            file_id=file_id,
            filename=file_record.filename,
        )
        return jsonify({
            'status': 'error',
            'data': {
                'passed': False,
                'expected_hash': file_record.file_hash,
                'computed_hash': computed_hash,
                'message': 'CRITICAL ALERT: File integrity violation detected! The file content or ciphertext has been altered.',
            }
        }), 200


# ---------------------------------------------------------------------------
# POST /api/files/<int:id>/simulate-tamper (Academic Live Demo for Review)
# ---------------------------------------------------------------------------
@files_bp.route('/<int:file_id>/simulate-tamper', methods=['POST'])
@token_required
def simulate_tamper(current_user_id, file_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    file_record = File.query.get(file_id)
    if not file_record or file_record.owner_id != current_user_id:
        return jsonify({'status': 'error', 'message': 'Owner access required'}), 403

    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file_record.stored_name)
    if not os.path.exists(file_path):
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    with open(file_path, 'rb') as fh:
        data = bytearray(fh.read())

    if len(data) == 0:
        return jsonify({'status': 'error', 'message': 'File is empty'}), 400

    # Flip bits at index 16 (in first ciphertext block)
    target_idx = min(16, len(data) - 1)
    data[target_idx] ^= 0xFF

    with open(file_path, 'wb') as fh:
        fh.write(data)

    file_record.is_tampered = True
    db.session.commit()

    log_security_event(
        event_type='FILE_TAMPER_SIMULATED',
        status='WARNING',
        details=f"SIMULATION: Injected 1-byte alteration into '{file_record.filename}' ciphertext to demonstrate O3 integrity protection",
        username=username,
        user_id=current_user_id,
        file_id=file_id,
        filename=file_record.filename,
    )

    return jsonify({
        'status': 'success',
        'message': f"Tamper simulated! Bit flipped in ciphertext of '{file_record.filename}'. Now run 'Verify Integrity' or try Download to see the security response.",
        'data': {'is_tampered': True}
    }), 200


# ---------------------------------------------------------------------------
# POST /api/files/<int:id>/restore-tamper (Restore original state)
# ---------------------------------------------------------------------------
@files_bp.route('/<int:file_id>/restore-tamper', methods=['POST'])
@token_required
def restore_tamper(current_user_id, file_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    file_record = File.query.get(file_id)
    if not file_record or file_record.owner_id != current_user_id:
        return jsonify({'status': 'error', 'message': 'Owner access required'}), 403

    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file_record.stored_name)
    backup_path = file_path + '.orig'

    if os.path.exists(backup_path):
        with open(backup_path, 'rb') as src, open(file_path, 'wb') as dst:
            dst.write(src.read())

    file_record.is_tampered = False
    db.session.commit()

    log_security_event(
        event_type='FILE_RESTORED',
        status='SUCCESS',
        details=f"Ciphertext for '{file_record.filename}' restored to clean original state",
        username=username,
        user_id=current_user_id,
        file_id=file_id,
        filename=file_record.filename,
    )

    return jsonify({
        'status': 'success',
        'message': f"Original ciphertext for '{file_record.filename}' restored. Integrity checks will now pass.",
        'data': {'is_tampered': False}
    }), 200


# ---------------------------------------------------------------------------
# DELETE /api/files/<int:id>
# ---------------------------------------------------------------------------
@files_bp.route('/<int:file_id>', methods=['DELETE'])
@token_required
def delete_file(current_user_id, file_id):
    user = User.query.get(current_user_id)
    username = user.username if user else 'Unknown'

    file_record = File.query.get(file_id)
    if not file_record:
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    if file_record.owner_id != current_user_id:
        return jsonify({'status': 'error', 'message': 'Only the owner can delete this file'}), 403

    filename = file_record.filename

    # Remove ciphertext files from disk
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file_record.stored_name)
    backup_path = file_path + '.orig'
    if os.path.exists(file_path):
        os.remove(file_path)
    if os.path.exists(backup_path):
        os.remove(backup_path)

    # Remove shares and file
    FileShare.query.filter_by(file_id=file_id).delete()
    db.session.delete(file_record)
    db.session.commit()

    log_security_event(
        event_type='FILE_DELETED',
        status='SUCCESS',
        details=f"Encrypted file '{filename}' and associated permissions purged from server",
        username=username,
        user_id=current_user_id,
        file_id=file_id,
        filename=filename,
    )

    return jsonify({
        'status': 'success',
        'message': f"File '{filename}' securely deleted",
        'data': {},
    }), 200
