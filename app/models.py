from datetime import datetime, timezone
import json
from app import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'user', 'admin'
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    files = db.relationship('File', backref='owner', lazy=True,
                            foreign_keys='File.owner_id')
    shares_created = db.relationship('FileShare', backref='sharer', lazy=True,
                                     foreign_keys='FileShare.shared_by')
    shares_received = db.relationship('FileShare', backref='recipient', lazy=True,
                                      foreign_keys='FileShare.shared_with')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class File(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)       # original name
    stored_name = db.Column(db.String(255), nullable=False, unique=True)  # UUID on disk
    file_hash = db.Column(db.String(64), nullable=False)       # Plaintext SHA-256 hex
    ciphertext_hash = db.Column(db.String(64), nullable=True)  # Ciphertext SHA-256 hex
    encrypted_key = db.Column(db.Text, nullable=False)         # hex-encoded wrapped AES key
    iv = db.Column(db.String(32), nullable=False)              # hex-encoded 16-byte IV
    cipher_algo = db.Column(db.String(30), default='AES-256-CBC', nullable=False)
    hash_algo = db.Column(db.String(20), default='SHA-256', nullable=False)
    size = db.Column(db.BigInteger, nullable=False)            # Plaintext size
    ciphertext_size = db.Column(db.BigInteger, nullable=True)  # Encrypted size
    is_tampered = db.Column(db.Boolean, default=False, nullable=False)
    uploaded_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    shares = db.relationship('FileShare', backref='file', lazy=True,
                             foreign_keys='FileShare.file_id')

    def to_dict(self):
        return {
            'id': self.id,
            'owner_id': self.owner_id,
            'owner_username': self.owner.username if self.owner else None,
            'filename': self.filename,
            'stored_name': self.stored_name,
            'file_hash': self.file_hash,
            'ciphertext_hash': self.ciphertext_hash,
            'iv': self.iv,
            'encrypted_key': self.encrypted_key,
            'cipher_algo': self.cipher_algo,
            'hash_algo': self.hash_algo,
            'size': self.size,
            'ciphertext_size': self.ciphertext_size or self.size,
            'is_tampered': self.is_tampered,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
        }


class FileShare(db.Model):
    __tablename__ = 'file_shares'

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    shared_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_with = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permission = db.Column(db.String(10), nullable=False, default='read')  # 'read' or 'write'
    shared_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'file_id': self.file_id,
            'filename': self.file.filename if self.file else 'Unknown',
            'file_size': self.file.size if self.file else 0,
            'file_hash': self.file.file_hash if self.file else None,
            'shared_by': self.shared_by,
            'sharer_username': self.sharer.username if self.sharer else 'Unknown',
            'shared_with': self.shared_with,
            'recipient_username': self.recipient.username if self.recipient else 'Unknown',
            'permission': self.permission,
            'shared_at': self.shared_at.isoformat() if self.shared_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'revoked': self.revoked,
        }


class SecurityAuditLog(db.Model):
    __tablename__ = 'security_audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)  # e.g., 'FILE_ENCRYPTED', 'INTEGRITY_CHECK_PASS'
    status = db.Column(db.String(20), nullable=False, default='SUCCESS')  # 'SUCCESS', 'WARNING', 'CRITICAL'
    username = db.Column(db.String(80), nullable=True)
    user_id = db.Column(db.Integer, nullable=True)
    file_id = db.Column(db.Integer, nullable=True)
    filename = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), default='127.0.0.1')
    details = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'status': self.status,
            'username': self.username or 'System',
            'user_id': self.user_id,
            'file_id': self.file_id,
            'filename': self.filename,
            'ip_address': self.ip_address,
            'details': self.details,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
