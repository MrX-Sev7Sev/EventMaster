from gevent import monkey
monkey.patch_all()

from flask import Flask
from .extensions import db, jwt
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
    app.config.from_object('config.Config')
    jwt.init_app(app)
    # Загрузка конфигурации
    
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
    
    # Регистрация blueprint (импортируем в последний момент)
    from .routes.auth import auth_bp
    from .routes.games import games_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(games_bp)
    
    return app
app = create_app()
