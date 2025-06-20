from gevent import monkey
monkey.patch_all()  # Должно быть первой строкой

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
import os

# Инициализация расширений (без привязки к app)
db = SQLAlchemy()
cors = CORS()
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()

def create_app():
    """Фабрика для создания Flask-приложения"""
    app = Flask(__name__)
    
    # 1. Загрузка конфигурации
    app.config.from_object('config.Config')
    
    # 2. Инициализация расширений с приложением
    db.init_app(app)
    cors.init_app(app, supports_credentials=True)
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # 3. Регистрация Blueprints (перенесено выше других настроек)
    register_blueprints(app)
    
    # 4. Настройка Flask-Login (после регистрации blueprints)
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User  # Ленивый импорт
        return User.query.get(int(user_id))
    
    # 5. JWT коллбэки
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        from .models import User
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()
    
    # 6. Создание таблиц БД
    with app.app_context():
        db.create_all()
    
    return app

def register_blueprints(app):
    """Регистрация всех Blueprint в приложении"""
    # Ленивые импорты внутри функции
    from app.routes.auth import bp as auth_bp
    from app.routes.games import bp as games_bp
    from app.routes.users import bp as users_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(games_bp)
    app.register_blueprint(users_bp)

# WSGI-совместимый объект
app = create_app()
