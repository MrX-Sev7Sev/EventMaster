from gevent import monkey
monkey.patch_all()  # Должно быть первой строкой

from flask import Flask, jsonify
from sqlalchemy import text, inspect
from config import config
from .extensions import db, jwt, login_manager, migrate

def create_app():
    """Фабрика для создания Flask-приложения"""
    app = Flask(__name__)
    
    # Загрузка конфигурации
    app.config.from_object(config)
    
    db.init_app(app)
    migrate.init_app(app, db)
    
    from .extensions import init_extensions
    init_extensions(app)
    
    @app.route('/api/test-db')
    def test_db():
        """Проверка подключения к базе данных"""
        try:
            from .extensions import db
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
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        app.logger.error(f"JWT Missing: {error}")
        return jsonify({"error": "Требуется авторизация"}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        app.logger.error(f"JWT Invalid: {error}")
        return jsonify({"error": "Неверный токен"}), 401
    
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
