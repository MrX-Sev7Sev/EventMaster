import os
from datetime import timedelta
from urllib.parse import quote_plus

class Config:
    def __init__(self):
        # Базовые настройки
        self.SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'production')
        
        # Обработка DATABASE_URL для Render
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            if db_url.startswith('postgres://'):
                db_url = db_url.replace('postgres://', 'postgresql://', 1)
            if '.onrender.com' in db_url:
                db_url += '?sslmode=require'
            self.SQLALCHEMY_DATABASE_URI = db_url
        else:
            # Локальная конфигурация (только для разработки)
            self.SQLALCHEMY_DATABASE_URI = (
                f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:"
                f"{quote_plus(os.getenv('POSTGRES_PASSWORD', ''))}@"
                f"{os.getenv('POSTGRES_HOST', 'localhost')}:"
                f"{os.getenv('POSTGRES_PORT', '5432')}/"
                f"{os.getenv('POSTGRES_DB', 'appdb')}"
            )
        
        # Обязательные настройки SQLAlchemy
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 5,
            'max_overflow': 10,
            'connect_args': {
                'connect_timeout': 5,
                'keepalives': 1,
                'keepalives_idle': 30,
                'keepalives_interval': 10,
                'keepalives_count': 5
            }
        }

        # JWT настройки
        self.JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', self.SECRET_KEY)
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
        
        # Настройки CORS
        CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'https://table-games.netlify.app,http://localhost:5173')

# Создаем экземпляр конфига
config = Config()
