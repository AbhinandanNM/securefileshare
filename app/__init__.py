import os

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
jwt = JWTManager()


def create_app(config_object=None):
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    app = Flask(__name__, static_folder=frontend_dir, static_url_path='')

    # --- Configuration ---
    if config_object is None:
        from config import Config
        app.config.from_object(Config)
    else:
        app.config.from_object(config_object)

    # Ensure upload folder exists relative to app root
    upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    if not os.path.isabs(upload_folder):
        upload_folder = os.path.join(app.root_path, '..', upload_folder)
    os.makedirs(upload_folder, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = os.path.abspath(upload_folder)

    # --- Extensions ---
    db.init_app(app)
    jwt.init_app(app)
    CORS(app, resources={r'/api/*': {'origins': '*'}})

    # --- JWT error handlers ---
    @jwt.unauthorized_loader
    def unauthorized_callback(reason):
        return jsonify({
            'status': 'error',
            'message': f'Missing or invalid token: {reason}',
            'data': {},
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(reason):
        return jsonify({
            'status': 'error',
            'message': f'Invalid token: {reason}',
            'data': {},
        }), 422

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'status': 'error',
            'message': 'Token has expired',
            'data': {},
        }), 401

    # --- Blueprints ---
    from app.auth import auth_bp
    from app.files import files_bp
    from app.shares import shares_bp
    from app.audit import audit_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(shares_bp)
    app.register_blueprint(audit_bp)

    # --- Frontend Routes ---
    @app.route('/')
    def serve_index():
        return send_from_directory(frontend_dir, 'index.html')

    @app.route('/dashboard')
    @app.route('/dashboard.html')
    def serve_dashboard():
        return send_from_directory(frontend_dir, 'dashboard.html')

    @app.route('/<path:path>')
    def serve_static(path):
        target = os.path.join(frontend_dir, path)
        if os.path.exists(target) and os.path.isfile(target):
            return send_from_directory(frontend_dir, path)
        return jsonify({'status': 'error', 'message': f'Not found: /{path}'}), 404

    # --- DB tables ---
    with app.app_context():
        db.create_all()

    return app
