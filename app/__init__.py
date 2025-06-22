from gevent import monkey
monkey.patch_all()  # Должно быть первой строкой

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from flask import Blueprint
from app.routes import register_blueprints
import os 
from .extensions import db, mail, cors, jwt, login_manager

# Инициализация расширений (без привязки к app)
cors = CORS()
jwt = JWTManager()
login_manager = LoginManager()
mail = Mail()
main_bp = Blueprint('main', __name__)

def home():
    return "Welcome to EventMaster API", 200
    
def create_app():
    """Фабрика для создания Flask-приложения"""
    app = Flask(__name__)
    
    # 1. Загрузка конфигурации
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://mrx:2IAsjs5oOfdEgB2pacpqdPZbhaMOmFN1@dpg-d1aj6jmmcj7s73fjkdu0-a/urfutable'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'd2еlf43!kL_42$%k42Qwgaa1@fkEjd*daP2')
    app.config.from_object('config.Config')
    # 2. Инициализация расширений с приложением
    from .extensions import db, login_manager
    db.init_app(app)
    cors.init_app(app, supports_credentials=True)
    jwt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    # CORS с конкретными настройками    
   ### CORS(app, resources={
   #     r"/api/*": {
   #         "origins": [
    #            "https://table-games.netlify.app",
     #           "http://localhost:5173"  # Для разработки
      #      ],
       #     "methods": ["GET", "POST", "PUT", "DELETE"],
        #    "allow_headers": ["Content-Type", "Authorization"]
       # }
    #}) 
    @app.route('/api/test-db')
    def test_db():
        try:
            from sqlalchemy import text, inspect
            
            # 1. Проверяем подключение
            result = db.session.execute(text("SELECT 1")).scalar()
            
            # 2. Получаем список таблиц (совместимый с SQLAlchemy 2.0+)
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
    
    @app.route('/')  # ← Это главное!
    def hello():
        return "Hello World (экстренная проверка)"
    
    # 3. Регистрация Blueprints (перенесено выше других настроек)
    register_blueprints(app)
    
    @app.route('/api/routes')
    def list_routes():
        """Отладочный endpoint: показывает все зарегистрированные маршруты"""
        routes = []
        for rule in app.url_map.iter_rules():
            # Игнорируем статические пути и /api/routes сам себя
            if not any([
                rule.rule.startswith('/static/'),
                rule.rule == '/api/routes',
                'debugtoolbar' in rule.endpoint  # Если используете Flask-DebugToolbar
            ]):
                routes.append({
                    "endpoint": rule.endpoint,
                    "path": rule.rule,
                    "methods": sorted(list(rule.methods - {'HEAD', 'OPTIONS'}))
                })
        return jsonify({"routes": sorted(routes, key=lambda x: x['path'])})

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
    """Регистрация всех Blueprint с явным контролем префиксов"""
    # Импортируем все blueprints
    from .utils import utils_bp  # Префикс задается только здесь
    from app.routes.auth import auth_bp    # Уже имеет prefix='/api/auth'
    from app.routes.games import games_bp  # Уже имеет prefix='/api/games'
    from app.routes.users import users_bp  # Уже имеет prefix='/api/users'
    from app.routes.data import data_bp, test_bp    # Уже имеет prefix='/api/data' # Импортируем оба blueprint из data.py
    from app.routes.test import test_bp    # Уже имеет prefix='/api/test'

    # Регистрация с явным указанием префиксов (если не заданы в самих blueprints)
    app.register_blueprint(utils_bp, url_prefix='/api/utils')
    app.register_blueprint(data_bp)    # Префикс уже задан в data.py
    app.register_blueprint(auth_bp)    # Префикс уже задан в auth.py
    app.register_blueprint(games_bp)   # Префикс уже задан в games.py
    app.register_blueprint(users_bp)   # Префикс уже задан в users.py
    app.register_blueprint(test_bp)    # Префикс уже задан в test.py

# WSGI-совместимый объект
app = create_app()
