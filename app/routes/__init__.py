from .auth import bp as auth_bp
from .users import users_bp
from .games import games_bp

__all__ = ['auth_bp', 'users_bp', 'games_bp']

def register_blueprints(app):
    """Регистрирует все blueprints в приложении"""
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(games_bp)
