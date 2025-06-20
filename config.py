import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    
    # Настройки PostgreSQL (основная БД)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-только-для-теста'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY не задан в переменных окружения!")

    # Настройки БД (приоритет: DATABASE_URL > индивидуальные переменные)
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://mrx:2IAsjs5oOfdEgB2pacpqdPZbhaMOmFN1@dpg-d1aj6jmmcj7s73fjkdu0-a.oregon-postgres.render.com/urfutable')
    
    if DATABASE_URL:
        # Если есть DATABASE_URL, используем его
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Иначе собираем из отдельных переменных (для PostgreSQL)
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
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
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
        # Проверка обязательных настроек
    @classmethod
    def validate_oauth(cls):
        required = [
            'MAIL_CLIENT_ID',
            'MAIL_CLIENT_SECRET',
            'MAIL_REDIRECT_URI'
        ]
        missing = [var for var in required if not getattr(cls, var)]
        if missing:
            raise ValueError(f"Missing Mail OAuth config: {', '.join(missing)}")

    SECRET_KEY = os.getenv('SECRET_KEY', 'd2Flf93!kL_42$%k2Qz1@fkEjd*daP2')  #
Config.validate()
Config.validate_oauth()
