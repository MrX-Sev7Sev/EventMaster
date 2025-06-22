from gevent import monkey
monkey.patch_all()  # Должно быть первой строкой

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from sqlalchemy import text, inspect
from config import config

# Инициализация расширений
db = SQLAlchemy()
cors = CORS(
    resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'].split(','),
            "supports_credentials": True,
            "methods": app.config['CORS_METHODS'],
            "allow_headers": app.config['CORS_ALLOW_HEADERS']
        }
    }
)
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()

def create_app():
    """Фабрика для создания Flask-приложения"""
    app = Flask(__name__)
    
    # Загрузка конфигурации
    app.config.from_object(config)
    
    # Инициализация расширений с приложением
    db.init_app(app)
    cors.init_app(app)
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    from flask_migrate import Migrate
    migrate = Migrate(app, db)
    
    @app.route('/api/test-db')
    def test_db():
        """Проверка подключения к базе данных"""
        try:
            result = db.session.execute(text("SELECT 1")).scalar()
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            return jsonify({
                "status": "success",
                "db_connection": "OK",
                "tables": tables
            }), 200
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "error": str(e),
                "type": type(e).__name__
            }), 500

    @app.route('/')
    def home():
        """Корневой маршрут для проверки работы API"""
        return "Welcome to EventMaster API", 200
    
    @app.route('/api/routes')
    def list_routes():
        """Отображает все зарегистрированные маршруты"""
        routes = []
        for rule in app.url_map.iter_rules():
            if not any([
                rule.rule.startswith('/static/'),
                rule.rule == '/api/routes',
                'debugtoolbar' in rule.endpoint
            ]):
                routes.append({
                    "endpoint": rule.endpoint,
                    "path": str(rule),
                    "methods": sorted(list(rule.methods - {'HEAD', 'OPTIONS'}))
                })
        return jsonify({"routes": sorted(routes, key=lambda x: x['path'])})

    # Регистрация blueprints
    register_blueprints(app)
    
    # Настройка аутентификации
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))
    
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        from .models import User
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()
    
    # Создание таблиц БД
    with app.app_context():
        db.create_all()
    
    return app

def register_blueprints(app):
    """Регистрирует все модули маршрутов"""
    from .utils import utils_bp
    from .routes.auth import auth_bp
    from .routes.games import games_bp
    from .routes.users import users_bp
    from .routes.data import data_bp, test_bp

    app.register_blueprint(utils_bp, url_prefix='/api/utils')
    app.register_blueprint(auth_bp)
    app.register_blueprint(games_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(data_bp)
    app.register_blueprint(test_bp)

# WSGI-совместимый объект
app = create_app()
