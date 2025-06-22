import os
from datetime import timedelta
from urllib.parse import quote_plus

class Config:
    def __init__(self):
        # Базовые настройки
        if 'RENDER' in os.environ:
            self.SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL'].replace(
                'postgres://', 'postgresql://', 1
            ) + '?sslmode=require'
        self.SECRET_KEY = os.getenv('SECRET_KEY')
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'production')
        
        # Настройки базы данных
        db_url = os.getenv('DATABASE_URL')
        if db_url and db_url.startswith('postgres://'):
            # Для Render.com и подобных сервисов
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
            if '.render.com' in db_url:
                db_url += '?sslmode=require'
            self.SQLALCHEMY_DATABASE_URI = db_url
        elif db_url:
            # Если DATABASE_URL уже в правильном формате
            self.SQLALCHEMY_DATABASE_URI = db_url
        else:
            # Для локальной разработки
            self.SQLALCHEMY_DATABASE_URI = (
                f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:"
                f"{quote_plus(os.getenv('POSTGRES_PASSWORD', ''))}@"
                f"{os.getenv('POSTGRES_HOST', 'localhost')}:"
                f"{os.getenv('POSTGRES_PORT', '5432')}/"
                f"{os.getenv('POSTGRES_DB', 'appdb')}"
            )
        
        # Убедимся, что URI установлен
        if not hasattr(self, 'SQLALCHEMY_DATABASE_URI'):
            raise ValueError("Database URI configuration is missing")
        
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 5,
            'max_overflow': 10,
            'connect_args': {
                'sslmode': 'require'
            }
        }

        # Настройки JWT
        self.JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', self.SECRET_KEY)
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

        # Настройки CORS
        self.CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5173,https://table-games.netlify.app').split(',')
        self.CORS_SUPPORTS_CREDENTIALS = True
        self.CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        self.CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']

        # Настройки почты
        self.MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.mail.ru')
        self.MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
        self.MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'true').lower() == 'true'
        self.MAIL_USERNAME = os.getenv('MAIL_USERNAME')
        self.MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
        self.MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', self.MAIL_USERNAME)

# Создаем экземпляр конфига
try:
    config = Config()
except ValueError as e:
    print(f"Configuration error: {e}")
    # Здесь вы можете добавить логику для аварийного завершения или использования значений по умолчанию
    raise
