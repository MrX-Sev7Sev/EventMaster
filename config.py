import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'  # SQLite для примера
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAILRU_CLIENT_ID = os.getenv('890ea7b9c21d4fe98aeccd1a457dc9fc')
    MAILRU_CLIENT_SECRET = os.getenv('19ef2f3739f1461d9adc5894ecfc0f13')
    MAILRU_REDIRECT_URI = 'https://boardinggames.ru'