from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required


def token_required(f):
    """
    Decorator that enforces a valid JWT access token.
    Wraps flask_jwt_extended's @jwt_required() and injects
    `current_user_id` (int) as the first positional argument to the view.
    """
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        try:
            current_user_id = int(get_jwt_identity())
        except (TypeError, ValueError):
            return jsonify({
                'status': 'error',
                'message': 'Invalid token identity',
                'data': {},
            }), 401
        return f(current_user_id, *args, **kwargs)
    return decorated
