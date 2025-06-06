import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-123')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # VK OAuth settings
    VK_APP_ID = '53575705'
    VK_APP_SECRET = 'RTgjgExUAfBsNHGnUDhA'
    VK_REDIRECT_URI = 'https://boardinggames.ru'
    
    # Email settings
    MAIL_SERVER = 'smtp.yourmailserver.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER')
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS')