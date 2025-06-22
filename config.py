import os
import re
from datetime import timedelta
from urllib.parse import quote_plus

class Config:
    # Базовые настройки
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    
    # База данных
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'max_overflow': 10,
        'connect_args': {
            'sslmode': 'require'
        }
    }
    
    @property
    def SQLALCHEMY_DATABASE_URI(self):
        if db_url := os.getenv('DATABASE_URL'):
            db_url = db_url.replace('postgres://', 'postgresql://')
            if '.render.com' in db_url:
                db_url = re.sub(
                    r'postgresql://(.+?)@(.+?)\.(?:oregon-postgres\.)?render\.com',
                    r'postgresql://\1@\2',
                    db_url
                )
            return db_url
        
        return f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:{quote_plus(os.getenv('POSTGRES_PASSWORD', ''))}@{os.getenv('POSTGRES_HOST', 'localhost')}:{os.getenv('POSTGRES_PORT', '5432')}/{os.getenv('POSTGRES_DB', 'appdb')}"

    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5173,https://table-games.netlify.app').split(',')
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']
    
    # Почта
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.mail.ru')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'true').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    
    # OAuth Mail.ru
    MAIL_CLIENT_ID = os.getenv('MAIL_OAUTH_CLIENT_ID', '890ea7b9c21d4fe98aeccd1a457dc9fc')
    MAIL_CLIENT_SECRET = os.getenv('MAIL_OAUTH_CLIENT_SECRET', '19ef2f3739f1461d9adc5894ecfc0f13')
    MAIL_REDIRECT_URI = os.getenv(
        'MAIL_OAUTH_REDIRECT_URI',
        'https://your-service.onrender.com/auth/mail/callback'
    )
    MAIL_AUTH_URL = 'https://oauth.mail.ru/login'
    MAIL_TOKEN_URL = 'https://oauth.mail.ru/token'
    MAIL_USER_INFO_URL = 'https://oauth.mail.ru/userinfo'
    
    # Сериализатор
    SERIALIZER_SECRET_KEY = os.getenv('SERIALIZER_SECRET_KEY', SECRET_KEY)
    SERIALIZER_SALT = os.getenv('SERIALIZER_SALT', 'email-confirm-salt')

# Экземпляр конфигурации
config = Config()
