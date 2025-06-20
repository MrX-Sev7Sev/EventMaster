from gevent import monkey
monkey.patch_all()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
import os

# Инициализация расширений
db = SQLAlchemy()
cors = CORS()
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()

def create_app():
    """Фабрика для создания Flask-приложения"""
    app = Flask(__name__)
    jwt.init_app(app)
    # Загрузка конфигурации
    app.config.from_object('config.Config')
    # Инициализация модулей
    from . import auth, games  # Импорт после создания app
    app.register_blueprint(auth.bp)
    app.register_blueprint(games.bp)
    # Инициализация расширений
    db.init_app(app)
    cors.init_app(app, supports_credentials=True)
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Настройка Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User  # Ленивый импорт для избежания циклических зависимостей
        return User.query.get(int(user_id))
    
    # Регистрация Blueprints
    register_blueprints(app)
    
    # Создание таблиц БД (для первого запуска)
    with app.app_context():
        db.create_all()
        
    return app
    
def register_blueprints(app):
    """Регистрация всех Blueprint"""
    from app.routes.auth import auth_bp
    from app.routes.users import users_bp
    from app.routes.games import games_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(games_bp, url_prefix='/api/games')
    
app = create_app()
