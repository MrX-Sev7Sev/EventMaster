from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from flask_cors import CORS
from flask_migrate import Migrate

# Инициализация всех расширений
db = SQLAlchemy()
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()
cors = CORS()
migrate = Migrate()

def init_extensions(app):
    """Инициализирует все расширения с приложением"""
    # Инициализация CORS с конфигом из app
    cors.init_app(app, resources={
        r"/api/*": {
            "origins": app.config.get('CORS_ORIGINS', 'http://localhost:5173fafs').split(','),
            "supports_credentials": True,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Настройки Flask-Login
    login_manager.login_view = 'auth.login'
    
    # JWT коллбэки
    from app.models import User, TokenBlocklist
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()
    
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        token = TokenBlocklist.query.filter_by(jti=jti).first()
        return token is not None
