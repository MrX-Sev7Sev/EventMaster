import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    
    # Настройки PostgreSQL (основная БД)
    SECRET_KEY = os.getenv('urfu-table-ames-8%7284264240527516)128*1/52_3^`0(')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY не задан в переменных окружения!")

    # Настройки БД (приоритет: DATABASE_URL > индивидуальные переменные)
    DATABASE_URL = os.getenv('DATABASE_URL')
    
    if DATABASE_URL:
        # Если есть DATABASE_URL, используем его
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Иначе собираем из отдельных переменных (для PostgreSQL)
        POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
        POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
        POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
        POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5433')
        POSTGRES_DB = os.getenv('POSTGRES_DB', 'eventmaster')

        if not POSTGRES_PASSWORD:
            raise ValueError("POSTGRES_PASSWORD не задан!")

        SQLALCHEMY_DATABASE_URI = (
            f"postgresql://{POSTGRES_USER}:{quote_plus(POSTGRES_PASSWORD)}@"
            f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # Настройки Mail.ru OAuth
    MAIL_OAUTH = {
        'CLIENT_ID': os.getenv('MAIL_CLIENT_ID', '890ea7b9c21d4fe98aeccd1a457dc9fc'),  # Из .env
        'CLIENT_SECRET': os.getenv('MAIL_CLIENT_SERVER', '19ef2f3739f1461d9adc5894ecfc0f13'),
        'REDIRECT_URI': os.getenv('MAIL_REDIRECT_URI',
                                'https://eventmaster-0w4v.onrender.com/auth/mail/callback'),
        'AUTH_URL': 'https://oauth.mail.ru/login',
        'TOKEN_URL': 'https://oauth.mail.ru/token',
        'USER_INFO_URL': 'https://oauth.mail.ru/userinfo',
        'SCOPE': 'userinfo'  # Права доступа
    }
    # Проверка обязательных переменных
    @classmethod
    def validate(cls):
        required_vars = [
            'SECRET_KEY',
            'POSTGRES_PASSWORD',
            'MAIL_CLIENT_ID',
            'MAIL_CLIENT_SECRET'
        ]
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise EnvironmentError(
                f"Отсутствуют обязательные переменные окружения: {', '.join(missing)}"
            )
    SECRET_KEY = os.getenv('SECRET_KEY', 'urfu-table-ames-8%7284264240527516)128*1/52_3^`0(')  #
    Config.validate()
