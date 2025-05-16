from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app(config_class='app.config.Config'):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Инициализация расширений
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Импорт API после инициализации приложения
    from .api import init_api
    init_api(app)
    
    # Регистрация блюпринтов
    from app.routes import auth_bp, main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    login_manager.login_view = 'auth.login'
    
    with app.app_context():
        db.create_all()
    
    return app