from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from flask_cors import CORS
from flask_migrate import Migrate

# Инициализация расширений
db = SQLAlchemy()
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()
cors = CORS()
migrate = Migrate()

def init_extensions(app):
    """Инициализирует все расширения с приложением"""
    
    # SQLAlchemy
    db.init_app(app)
    
    # JWT
    jwt.init_app(app)
    
    # Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    # Flask-Mail
    mail.init_app(app)
    
    # CORS
    cors.init_app(app, resources={
        r"/api/*": {
            "origins": app.config.get('CORS_ORIGINS', ['*']),
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })
    
    # Flask-Migrate
    migrate.init_app(app, db)
    
    # Callback для загрузки пользователя
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    
    # Callback для проверки JWT токенов
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        from app.models import User
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()
    
    # Дополнительные JWT-коллбэки
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        from app.models import TokenBlocklist
        jti = jwt_payload["jti"]
        token = TokenBlocklist.query.filter_by(jti=jti).first()
        return token is not None
