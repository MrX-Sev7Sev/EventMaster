from flask import Flask, jsonify, request, redirect, url_for, session, flash, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import secrets
from urllib.parse import urlencode
import requests
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError
from config import Config

# Инициализация расширений
db = SQLAlchemy()
mail = Mail()
serializer = None

# Временные "базы данных" для примера
users_db = {}
games_db = []

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {
            'sslmode': 'require'  # Обязательно для Render PostgreSQL
        }
    }
    @app.route('/api/data')
    def data():
        return jsonify({"message": "Minimal working example"})
    # Инициализация расширений
    db.init_app(app)
    mail.init_app(app)
    global serializer
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    # Настройка CORS
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": ["http://localhost:5173", "https://table-games.netlify.app"],
                "methods": ["GET", "POST", "OPTIONS", "DELETE"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True
            }
        }
    )
    
    # Регистрация всех маршрутов
    register_auth_routes(app)
    register_user_routes(app)
    register_game_routes(app)
    register_utility_routes(app)
    
    # Создание таблиц при первом запуске
    with app.app_context():
        db.create_all()
    
    return app

def register_auth_routes(app):
    """Регистрация маршрутов аутентификации"""
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        user = users_db.get(email)
        if not user or user['password'] != password:
            return jsonify({"error": "Invalid credentials"}), 401
        
        return jsonify({
            "id": user['id'],
            "email": user['email'],
            "name": user['name']
        })

    @app.route('/api/register', methods=['POST'])
    def register():
        data = request.json
        email = data.get('email')
        
        if email in users_db:
            return jsonify({"error": "User already exists"}), 400
        
        user_id = str(len(users_db) + 1
        users_db[email] = {
            "id": user_id,
            "email": email,
            "password": data.get('password'),  # В реальном проекте нужно хешировать!
            "name": data.get('name', ''),
            "avatar": data.get('avatar', '')
        }
        
        return jsonify({"id": user_id}), 201

    @app.route('/api/auth/mail', methods=['GET'])
    def start_mail_oauth():
        """OAuth авторизация через Mail.ru"""
        state = secrets.token_urlsafe(32)
        params = {
            'response_type': 'code',
            'client_id': app.config['MAIL_CLIENT_ID'],
            'redirect_uri': app.config['MAIL_REDIRECT_URI'],
            'scope': 'userinfo',
            'state': state
        }
        
        auth_url = f"{app.config['MAIL_AUTH_URL']}?{urlencode(params)}"
        return jsonify({"auth_url": auth_url, "state": state})

    @app.route('/api/auth/mail/callback', methods=['POST'])
    def handle_mail_callback():
        """Обработка callback от Mail.ru"""
        data = request.get_json()
        
        if not data or 'code' not in data or 'state' not in data:
            return jsonify({"error": "Missing code or state"}), 400
        
        if data['state'] != data.get('client_state'):
            return jsonify({"error": "Invalid state"}), 403
        
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
            
            user_response = requests.get(
                app.config['MAIL_USER_INFO_URL'],
                params={'access_token': token_info['access_token']}
            )
            user_info = user_response.json()
            
            user = process_mail_user(user_info)
            
            return jsonify({
                "user_id": user.id,
                "access_token": generate_jwt(user.id),
                "email": user.email
            })
            
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"OAuth error: {str(e)}"}), 500

    @app.route('/logout')
    def logout():
        session.pop('username', None)
        return redirect(url_for('home'))

def register_user_routes(app):
    """Регистрация маршрутов для работы с пользователями"""
    
    @app.route('/api/users/<user_id>', methods=['GET'])
    def get_user(user_id):
        user = next((u for u in users_db.values() if u['id'] == user_id), None)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "id": user['id'],
            "email": user['email'],
            "name": user['name'],
            "avatar": user.get('avatar', '')
        })

    @app.route('/api/users/check/<email>', methods=['GET'])
    def check_user(email):
        exists = email in users_db
        return jsonify({"exists": exists})

    @app.route('/api/users/<user_id>', methods=['POST'])
    def update_user(user_id):
        data = request.json
        user = next((u for u in users_db.values() if u['id'] == user_id), None)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if 'name' in data:
            user['name'] = data['name']
        if 'avatar' in data:
            user['avatar'] = data['avatar']
        
        return jsonify({"status": "updated"})

def register_game_routes(app):
    """Регистрация маршрутов для работы с играми"""
    
    @app.route('/api/games', methods=['GET'])
    def get_games():
        return jsonify({"games": games_db})

    @app.route('/api/games', methods=['POST'])
    def create_game():
        game = request.json
        game['id'] = str(len(games_db) + 1)
        game['players'] = [game['creator_id']]
        games_db.append(game)
        return jsonify({"id": game['id']}), 201

    @app.route('/api/games/<game_id>', methods=['DELETE'])
    def delete_game(game_id):
        global games_db
        games_db = [g for g in games_db if g['id'] != game_id]
        return jsonify({"status": "deleted"})

    @app.route('/api/games/<game_id>', methods=['PUT'])
    def update_game(game_id):
        data = request.json
        game = next((g for g in games_db if g['id'] == game_id), None)
        if not game:
            return jsonify({"error": "Game not found"}), 404
        
        game.update(data)
        return jsonify({"status": "updated"})

    @app.route('/api/games/<game_id>/join', methods=['POST'])
    def join_game(game_id):
        user_id = request.json.get('user_id')
        game = next((g for g in games_db if g['id'] == game_id), None)
        if not game:
            return jsonify({"error": "Game not found"}), 404
        
        if user_id not in game['players']:
            game['players'].append(user_id)
        
        return jsonify({"status": "joined"})

    @app.route('/api/games/<game_id>/leave', methods=['POST'])
    def leave_game(game_id):
        user_id = request.json.get('user_id')
        game = next((g for g in games_db if g['id'] == game_id), None)
        if not game:
            return jsonify({"error": "Game not found"}), 404
        
        if user_id in game['players']:
            game['players'].remove(user_id)
        
        return jsonify({"status": "left"})

def register_utility_routes(app):
    """Регистрация вспомогательных маршрутов"""
    
    @app.route('/')
    def home():
        return {"message": "Добро пожаловать в клуб настольных игр!"}

    @app.route('/api/data', methods=['GET', 'OPTIONS'])
    def get_data():
        if request.method == 'OPTIONS':
            return jsonify({"status": "ok"}), 200
        return jsonify({"message": "Данные успешно получены!"})

    @app.after_request
    def add_mime_types(response):
        if response.content_type == 'application/octet-stream':
            if request.path.endswith('.jsx'):
                response.content_type = 'text/javascript'
        return response

    @app.route('/static/js/<path:filename>')
    def serve_js(filename):
        return send_from_directory('static/js', filename, mimetype='text/javascript')

    @app.route('/static/js/modules/<path:filename>')
    def serve_js_module(filename):
        return send_from_directory('static/js/modules', filename, mimetype='application/javascript')

    @app.route('/protected')
    @token_required
    def protected_route(user):
        return {'message': f'Hello, {user.username}'}

# Вспомогательные функции
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

def process_mail_user(user_data):
    """Обработка данных пользователя из Mail.ru"""
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

def generate_jwt(user_id):
    """Генерация JWT токена (заглушка)"""
    return f"generated-jwt-for-{user_id}"

# Модели (лучше вынести в отдельный файл models.py)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vk_id = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    remember_me = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)    
    mail_id = db.Column(db.String(50))
    avatar_url = db.Column(db.String(200))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    access_token = db.Column(db.String(500))
    expires_at = db.Column(db.DateTime)
    refresh_token = db.Column(db.String(500))

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
