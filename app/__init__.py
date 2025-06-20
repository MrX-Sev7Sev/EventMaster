from gevent import monkey
monkey.patch_all()  # Должно быть первой строкой

from flask import Flask
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
    
    # 2. Инициализация расширений
    db.init_app(app)
    cors.init_app(app, supports_credentials=True)
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # 3. Настройка Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User  # Ленивый импорт
        return User.query.get(int(user_id))
    
    # 4. Регистрация Blueprints (ленивые импорты)
    from .routes.auth import bp as auth_bp
    from .routes.games import bp as games_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(games_bp)
    
    # 5. Создание таблиц БД
    with app.app_context():
        db.create_all()
    
    return app

# WSGI-совместимый объект
app = create_app()
