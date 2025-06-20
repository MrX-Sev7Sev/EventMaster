import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    # Базовые настройки
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-только-для-теста')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Настройки подключения к БД
    DATABASE_URL = os.getenv('DATABASE_URL')
    
    if DATABASE_URL:
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
        POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
        POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
        POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
        POSTGRES_DB = os.getenv('POSTGRES_DB', 'eventmaster')
        
        if not POSTGRES_PASSWORD:
            raise ValueError("POSTGRES_PASSWORD не задан!")
            
        SQLALCHEMY_DATABASE_URI = (
            f"postgresql://{POSTGRES_USER}:{quote_plus(POSTGRES_PASSWORD)}@"
            f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )
    
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Настройки Mail.ru OAuth (перенесены в отдельные атрибуты класса)
    MAIL_CLIENT_ID = os.getenv('MAIL_CLIENT_ID', '890ea7b9c21d4fe98aeccd1a457dc9fc')
    MAIL_CLIENT_SECRET = os.getenv('MAIL_CLIENT_SECRET', '19ef2f3739f1461d9adc5894ecfc0f13')
    MAIL_REDIRECT_URI = os.getenv('MAIL_REDIRECT_URI',
                                'https://eventmaster-0w4v.onrender.com/auth/mail/callback')
    
    # Словарь OAuth настроек
    MAIL_OAUTH = {
        'CLIENT_ID': MAIL_CLIENT_ID,
        'CLIENT_SECRET': MAIL_CLIENT_SECRET,
        'REDIRECT_URI': MAIL_REDIRECT_URI,
        'AUTH_URL': 'https://oauth.mail.ru/login',
        'TOKEN_URL': 'https://oauth.mail.ru/token',
        'USER_INFO_URL': 'https://oauth.mail.ru/userinfo',
        'SCOPE': 'userinfo'
    }

    @classmethod
    def validate(cls):
        """Проверка обязательных переменных"""
        required = [
            'SECRET_KEY',
            'POSTGRES_PASSWORD' if not cls.DATABASE_URL else None,
            'MAIL_CLIENT_ID',
            'MAIL_CLIENT_SECRET'
        ]
        missing = [var for var in required if var and not os.getenv(var)]
        if missing:
            raise ValueError(
                f"Отсутствуют обязательные переменные: {', '.join(missing)}"
            )

    @classmethod
    def validate_oauth(cls):
        """Проверка настроек OAuth"""
        required = ['MAIL_CLIENT_ID', 'MAIL_CLIENT_SECRET', 'MAIL_REDIRECT_URI']
        missing = [var for var in required if not getattr(cls, var)]
        if missing:
            raise ValueError(f"Отсутствуют настройки OAuth: {', '.join(missing)}")

# Вызываем проверки после определения класса
Config.validate()
Config.validate_oauth()
