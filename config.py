import os
from datetime import timedelta
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    # ========== Базовые настройки ==========
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-только-для-теста')
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    
    # ========== Настройки базы данных ==========
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 20,
        'max_overflow': 30
    }
    
    # Автоматическое определение DSN для БД
    if os.getenv('DATABASE_URL'):
        SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    else:
        POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
        POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
        POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
        POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
        POSTGRES_DB = os.getenv('POSTGRES_DB', 'table_games')
        
        if not POSTGRES_PASSWORD:
            raise ValueError("POSTGRES_PASSWORD не задан!")
            
        SQLALCHEMY_DATABASE_URI = (
            f"postgresql://{POSTGRES_USER}:{quote_plus(POSTGRES_PASSWORD)}@"
            f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )

    # ========== Настройки аутентификации ==========
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    
    # ========== Настройки CORS ==========
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5173,https://table-games.netlify.app').split(',')
    CORS_SUPPORTS_CREDENTIALS = True
    
    # ========== Настройки почты ==========
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.mail.ru')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'false').lower() == 'true'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'true').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    
    # ========== OAuth Mail.ru ==========
    MAIL_OAUTH_CLIENT_ID = os.getenv('MAIL_OAUTH_CLIENT_ID', '890ea7b9c21d4fe98aeccd1a457dc9fc')
    MAIL_OAUTH_CLIENT_SECRET = os.getenv('MAIL_OAUTH_CLIENT_SECRET', '19ef2f3739f1461d9adc5894ecfc0f13')
    MAIL_OAUTH_REDIRECT_URI = os.getenv(
        'MAIL_OAUTH_REDIRECT_URI',
        'https://eventmaster-0w4v.onrender.com/auth/mail/callback'
    )
    
    @property
    def MAIL_OAUTH_CONFIG(self):
        return {
            'client_id': self.MAIL_OAUTH_CLIENT_ID,
            'client_secret': self.MAIL_OAUTH_CLIENT_SECRET,
            'redirect_uri': self.MAIL_OAUTH_REDIRECT_URI,
            'auth_url': 'https://oauth.mail.ru/login',
            'token_url': 'https://oauth.mail.ru/token',
            'user_info_url': 'https://oauth.mail.ru/userinfo',
            'scope': 'userinfo'
        }

    # ========== Валидация конфигурации ==========
    @classmethod
    def validate(cls):
        """Проверка обязательных переменных окружения"""
        required = [
            'SECRET_KEY',
            'POSTGRES_PASSWORD' if not os.getenv('DATABASE_URL') else None,
            'MAIL_USERNAME' if cls.FLASK_ENV == 'production' else None,
            'MAIL_PASSWORD' if cls.FLASK_ENV == 'production' else None
        ]
        
        missing = [var for var in required if var and not os.getenv(var)]
        if missing:
            raise ValueError(
                f"Отсутствуют обязательные переменные окружения: {', '.join(missing)}"
            )

# Автоматическая валидация при импорте
Config.validate()
