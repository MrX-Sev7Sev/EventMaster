from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import requests
from datetime import datetime, timedelta
from .models import User, UserToken  # Предполагается, что модели уже есть
from . import db  
from config import Config 
from urllib.parse import urlencode
import secrets
from .models import User, UserToken 
from flask_login import login_user
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = Flask(__name__)
app.config.from_object(Config)
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:5173", "https://table-games.netlify.app/"],
            "methods": ["GET", "POST", "OPTIONS", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    }
)
app.config['SECRET_KEY'] = 'urfu-table-ames-8%7284264240527516)128*1/52_3^`0('
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@host:port/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CORS для фронта
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # URL вашего фронта
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vk_id = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    remember_me = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    access_token = db.Column(db.String(500))  # Токен от VK
    expires_at = db.Column(db.DateTime)  # Когда истекает
    refresh_token = db.Column(db.String(500))  # Для обновления (если есть)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Создаем таблицы при первом запуске
with app.app_context():
    db.create_all()
    
@app.get("/")
def read_root():
    return {"message": "Добро пожаловать в клуб настольных игр!"}

@app.route('/api/data', methods=['GET', 'OPTIONS'])
def get_data():
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200
    return jsonify({"message": "Данные успешно получены!"})

@app.after_request
def add_mime_types(response):
    if response.content_type == 'application/octet-stream':
        # Исправляем MIME-тип для .jsx
        if request.path.endswith('.jsx'):
            response.content_type = 'text/javascript'
    return response
    
# Правильная отдача JS-файлов с заголовком Content-Type
@app.route('/static/js/<path:filename>')
def serve_js(filename):
    return send_from_directory('static/js', filename, mimetype='text/javascript')

# Для модулей (если используется type="module")
@app.route('/static/js/modules/<path:filename>')
def serve_js_module(filename):
    return send_from_directory('static/js/modules', filename, mimetype='application/javascript')

@app.route('/api/register', methods=['POST'])  # Явно указываем /api/ для API
def register():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    
    # Валидация обязательных полей
    required_fields = ['username', 'email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    username = data['username']
    email = data['email']
    password = data['password']
    
    # Проверка существования пользователя
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409
        
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already in use"}), 409
    
    # Создание пользователя
    try:
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Возвращаем созданного пользователя (без пароля)
        return jsonify({
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
  
@app.route('/api/auth/mail', methods=['GET'])
def start_mail_oauth():
    """
    Возвращает URL для OAuth-авторизации Mail.ru
    Клиент должен перенаправить пользователя на этот URL
    """
    state = secrets.token_urlsafe(32)  # CSRF-токен
    params = {
        'response_type': 'code',
        'client_id': app.config['MAIL_CLIENT_ID'],
        'redirect_uri': app.config['MAIL_REDIRECT_URI'],
        'scope': 'userinfo',
        'state': state
    }
    
    auth_url = f"{app.config['MAIL_AUTH_URL']}?{urlencode(params)}"
    
    # Возвращаем URL и state (клиент должен проверить state при callback)
    return jsonify({
        "auth_url": auth_url,
        "state": state  # Клиент должен сохранить этот state
    })

import requests

@app.route('/api/auth/mail/callback', methods=['POST'])
def handle_mail_callback():
    """
    Обработка callback от Mail.ru.
    Клиент должен прислать код и state.
    """
    data = request.get_json()
    
    # Проверка входных данных
    if not data or 'code' not in data or 'state' not in data:
        return jsonify({"error": "Missing code or state"}), 400
    
    # Проверка state (должен сравниться с тем, что получил клиент)
    # Клиент должен передать сохранённый state
    if data['state'] != data.get('client_state'):
        return jsonify({"error": "Invalid state"}), 403
    
    # Обмен кода на токен
    try:
        token_data = {
            'client_id': app.config['MAIL_CLIENT_ID'],
            'client_secret': app.config['MAIL_CLIENT_SECRET'],
            'grant_type': 'authorization_code',
            'code': data['code'],
            'redirect_uri': app.config['MAIL_REDIRECT_URI']
        }
        
        token_response = requests.post(app.config['MAIL_TOKEN_URL'], data=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()
        
        # Получение данных пользователя
        user_response = requests.get(
            app.config['MAIL_USER_INFO_URL'],
            params={'access_token': token_info['access_token']}
        )
        user_info = user_response.json()
        
        # Создание/обновление пользователя в БД
        user = process_mail_user(user_info)
        
        # Возвращаем JWT-токен или данные пользователя
        return jsonify({
            "user_id": user.id,
            "access_token": generate_jwt(user.id),  # Ваша реализация JWT
            "email": user.email
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"OAuth error: {str(e)}"}), 500

def process_mail_user(user_data):
    """
    Создаёт или обновляет пользователя в БД.
    Возвращает объект User.
    """
    user = User.query.filter_by(mail_id=user_data.get('id')).first()
    
    if not user:
        user = User(
            mail_id=user_data['id'],
            email=user_data.get('email'),
            username=user_data.get('name'),
            avatar_url=user_data.get('image')
        )
        db.session.add(user)
    else:
        if 'email' in user_data:
            user.email = user_data['email']
        if 'name' in user_data:
            user.username = user_data['name']
    
    db.session.commit()
    return user

@app.route('/login/mail/callback')
def mail_callback():
    """Обработка OAuth-колбэка от Mail.ru с использованием config.py"""
    
    # 1. Получаем код из URL
    code = request.args.get('code')
    if not code:
        flash('Ошибка: код авторизации не получен', 'error')
        return redirect(url_for('login'))

    try:
        # 2. Обмениваем код на access token (используем данные из config.py)
        token_data = {
            'client_id': Config.MAIL_OAUTH['CLIENT_ID'],
            'client_secret': Config.MAIL_OAUTH['CLIENT_SECRET'],
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': Config.MAIL_OAUTH['REDIRECT_URI']
        }
        
        token_response = requests.post(
            Config.MAIL_OAUTH['TOKEN_URL'],
            data=token_data
        ).json()
        
        access_token = token_response['access_token']

        # 3. Получаем данные пользователя
        user_info = requests.get(
            Config.MAIL_OAUTH['USER_INFO_URL'],
            params={'access_token': access_token}
        ).json()

        # 4. Ищем или создаем пользователя в БД
        user = User.query.filter_by(mail_id=user_info['id']).first()
        if not user:
            user = User(
                mail_id=user_info['id'],
                email=user_info.get('email'),
                name=user_info.get('name'),
                avatar=user_info.get('image')
            )
            db.session.add(user)
            db.session.commit()

        # 5. Сохраняем токен (если нужно)
        user_token = UserToken(
            user_id=user.id,
            access_token=access_token,
            expires_at=datetime.utcnow() + timedelta(seconds=token_response['expires_in'])
        )
        db.session.add(user_token)
        db.session.commit()

        # 6. Логиним пользователя
        login_user(user)
        flash('Успешный вход через Mail.ru!', 'success')

    except Exception as e:
        flash(f'Ошибка авторизации: {str(e)}', 'error')
        return redirect(url_for('login'))

    return redirect(url_for('home'))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {'error': 'Token is missing'}, 401
        
        user_token = UserToken.query.filter_by(access_token=token).first()
        if not user_token or user_token.expires_at < datetime.utcnow():
            return {'error': 'Invalid or expired token'}, 401
        
        return f(user_token.user, *args, **kwargs)
    return decorated

@app.route('/protected')
@token_required
def protected_route(user):
    return {'message': f'Hello, {user.username}'}
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/')  
def example():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=True)
