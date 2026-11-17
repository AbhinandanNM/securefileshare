import bcrypt
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token

from app import db
from app.audit_service import log_security_event
from app.middleware import token_required
from app.models import User

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''

    # Validation
    if not username or not email or not password:
        return jsonify({
            'status': 'error',
            'message': 'Username, email and password are required',
            'data': {},
        }), 400

    if len(password) < 6:
        return jsonify({
            'status': 'error',
            'message': 'Password must be at least 6 characters long',
            'data': {},
        }), 400

    if User.query.filter_by(username=username).first():
        return jsonify({
            'status': 'error',
            'message': 'Username already taken',
            'data': {},
        }), 409

    if User.query.filter_by(email=email).first():
        return jsonify({
            'status': 'error',
            'message': 'Email already registered',
            'data': {},
        }), 409

    # Objective O1: Password Hashing using bcrypt (adaptive blowfish)
    password_hash = bcrypt.hashpw(
        password.encode('utf-8'), bcrypt.gensalt(rounds=12)
    ).decode('utf-8')

    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    log_security_event(
        event_type='USER_REGISTER',
        status='SUCCESS',
        details=f"New user registered with bcrypt hashing (rounds=12): '{username}'",
        username=username,
        user_id=user.id
    )

    return jsonify({
        'status': 'success',
        'message': 'User registered successfully with bcrypt credential protection',
        'data': user.to_dict(),
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({
            'status': 'error',
            'message': 'Username and password are required',
            'data': {},
        }), 400

    user = User.query.filter_by(username=username).first()

    if not user or not bcrypt.checkpw(
        password.encode('utf-8'), user.password_hash.encode('utf-8')
    ):
        log_security_event(
            event_type='USER_LOGIN_FAILED',
            status='WARNING',
            details=f"Failed login attempt for username '{username}' - Invalid credentials",
            username=username
        )
        return jsonify({
            'status': 'error',
            'message': 'Invalid username or password',
            'data': {},
        }), 401

    # Issue JWT token (Objective O1: Stateless Cryptographic Authentication)
    access_token = create_access_token(identity=str(user.id))

    log_security_event(
        event_type='USER_LOGIN_SUCCESS',
        status='SUCCESS',
        details=f"User authenticated successfully via JWT (HS256)",
        username=user.username,
        user_id=user.id
    )

    return jsonify({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'access_token': access_token,
            'user': user.to_dict(),
            'auth_method': 'JWT (HMAC-SHA256)',
            'credential_security': 'bcrypt-12',
        },
    }), 200


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user(current_user_id):
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    return jsonify({
        'status': 'success',
        'data': user.to_dict()
    }), 200
