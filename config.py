import os
import re
from datetime import timedelta
from urllib.parse import quote_plus

class Config:
    def __init__(self):
        # Базовые настройки
        self.SECRET_KEY = os.getenv('SECRET_KEY')
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'production')
        
        # База данных
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 5,
            'max_overflow': 10,
            'connect_args': {'sslmode': 'require'}
        }
        
        # База данных
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            db_url = db_url.replace('postgres://', 'postgresql://')
            if '.render.com' in db_url:
                db_url += '?sslmode=require'
            self.SQLALCHEMY_DATABASE_URI = db_url
        else:
            self.SQLALCHEMY_DATABASE_URI = (
                f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:"
                f"{quote_plus(os.getenv('POSTGRES_PASSWORD', ''))}@"
                f"{os.getenv('POSTGRES_HOST', 'localhost')}:"
                f"{os.getenv('POSTGRES_PORT', '5432')}/"
                f"{os.getenv('POSTGRES_DB', 'appdb')}"
            )

        # JWT
        self.JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', self.SECRET_KEY)
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        self.JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
        
        # CORS
        self.CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5173,https://table-games.netlify.app').split(',')
        self.CORS_SUPPORTS_CREDENTIALS = True
        self.CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        self.CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']
        
        self.MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.mail.ru')
        self.MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
        self.MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'true').lower() == 'true'
        self.MAIL_USERNAME = os.getenv('MAIL_USERNAME')
        self.MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
        self.MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', self.MAIL_USERNAME)
        
        self.MAIL_CLIENT_ID = os.getenv('MAIL_OAUTH_CLIENT_ID')
        self.MAIL_CLIENT_SECRET = os.getenv('MAIL_OAUTH_CLIENT_SECRET')
        self.MAIL_REDIRECT_URI = os.getenv(
            'MAIL_OAUTH_REDIRECT_URI',
            'https://eventmaster-0w4v.onrender.com/auth/mail/callback'
        )
        self.MAIL_AUTH_URL = 'https://oauth.mail.ru/login'
        self.MAIL_TOKEN_URL = 'https://oauth.mail.ru/token'
        self.MAIL_USER_INFO_URL = 'https://oauth.mail.ru/userinfo'
        
        self.SERIALIZER_SECRET_KEY = os.getenv('SERIALIZER_SECRET_KEY', self.SECRET_KEY)
        self.SERIALIZER_SALT = os.getenv('SERIALIZER_SALT', 'email-confirm-salt')

# Создаем экземпляр конфига
config = Config()
