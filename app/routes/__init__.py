from .auth import auth_bp
from .users import users_bp
from .games import games_bp
from .data import data_bp

__all__ = ['auth_bp', 'users_bp', 'games_bp', 'data_bp']

# app/routes/__init__.py
def register_blueprints(app):
    app.register_blueprint(auth_bp)  # Без url_prefix
    app.register_blueprint(users_bp)
    app.register_blueprint(games_bp)
    app.register_blueprint(data_bp)
