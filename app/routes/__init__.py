# app/routes/__init__.py
from .auth import auth_bp
from .users import users_bp
from .games import games_bp
from .data import data_bp

# Для явного экспорта (если используется from app.routes import *)
__all__ = ['auth_bp', 'users_bp', 'games_bp', 'data_bp', 'register_blueprints']

def register_blueprints(app):
    """Регистрирует все blueprints в Flask-приложении"""
    app.register_blueprint(auth_bp)    # Префикс /api/auth задан в auth.py
    app.register_blueprint(users_bp)   # Префикс /api/users задан в users.py
    app.register_blueprint(games_bp)   # Префикс /api/games задан в games.py
    app.register_blueprint(data_bp)    # Префикс /api/data задан в data.py
