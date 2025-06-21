from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail
import secrets
from urllib.parse import urlencode
import requests
from functools import wraps
from config import Config
import os

# Инициализация расширений
db = SQLAlchemy()
mail = Mail()
serializer = None

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Инициализация расширений
    db.init_app(app)
    mail.init_app(app)
    global serializer
    serializer = URLSafeTimedSerializer(
        app.config['SERIALIZER_SECRET_KEY'],
        salt=app.config['SERIALIZER_SALT']
    )
    
    # Настройка CORS
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": app.config['CORS_ORIGINS'],
                "supports_credentials": app.config['CORS_SUPPORTS_CREDENTIALS'],
                "methods": app.config['CORS_METHODS'],
                "allow_headers": app.config['CORS_ALLOW_HEADERS']
            }
        }
    )
    
    # Универсальный обработчик CORS
    @app.after_request
    def add_cors_headers(response):
        if request.path.startswith('/api/'):
            response.headers.add('Access-Control-Allow-Origin', ', '.join(app.config['CORS_ORIGINS']))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Allow-Headers', ', '.join(app.config['CORS_ALLOW_HEADERS']))
            response.headers.add('Access-Control-Allow-Methods', ', '.join(app.config['CORS_METHODS']))
        return response

    # Регистрация маршрутов
    register_auth_routes(app)
    register_user_routes(app)
    register_game_routes(app)
    register_utility_routes(app)
    
    # Создание таблиц
    with app.app_context():
        db.create_all()
    
    return app
    
def register_auth_routes(app):
    """Регистрация маршрутов аутентификации"""
    
    @app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
    def login():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        
        if not user or not user.check_password(data.get('password')):
            return jsonify({"error": "Invalid credentials"}), 401
            
        return jsonify({
            "id": user.id,
            "email": user.email,
            "name": user.username
        })

    @app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
    def register():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        data = request.get_json()
        if User.query.filter_by(email=data.get('email')).first():
            return jsonify({"error": "User exists"}), 400
            
        user = User(
            email=data['email'],
            username=data.get('name', ''),
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        
        return jsonify({"id": user.id}), 201

    @app.route('/api/auth/mail', methods=['GET', 'OPTIONS'])
    def start_mail_oauth():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
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

    @app.route('/api/auth/mail/callback', methods=['POST', 'OPTIONS'])
    def handle_mail_callback():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
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

def register_user_routes(app):
    """Регистрация маршрутов для работы с пользователями"""
    
    @app.route('/api/users/<int:user_id>', methods=['GET', 'OPTIONS'])
    def get_user(user_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        user = User.query.get_or_404(user_id)
        return jsonify({
            "id": user.id,
            "email": user.email,
            "name": user.username,
            "avatar": user.avatar_url if hasattr(user, 'avatar_url') else ''
        })

def register_game_routes(app):
    """Регистрация маршрутов для работы с играми"""
    games_db = []  # Временное хранилище для примера
    
    @app.route('/api/games', methods=['GET', 'OPTIONS'])
    def get_games():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"games": games_db})

    @app.route('/api/games', methods=['POST', 'OPTIONS'])
    def create_game():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        game = request.json
        game['id'] = str(len(games_db) + 1)
        game['players'] = [game['creator_id']]
        games_db.append(game)
        return jsonify({"id": game['id']}), 201

    @app.route('/api/games/<game_id>', methods=['DELETE', 'OPTIONS'])
    def delete_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        global games_db
        games_db = [g for g in games_db if g['id'] != game_id]
        return jsonify({"status": "deleted"})

    @app.route('/api/games/<game_id>', methods=['PUT', 'OPTIONS'])
    def update_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        data = request.json
        game = next((g for g in games_db if g['id'] == game_id), None)
        if not game:
            return jsonify({"error": "Game not found"}), 404
        
        game.update(data)
        return jsonify({"status": "updated"})

    @app.route('/api/games/<game_id>/join', methods=['POST', 'OPTIONS'])
    def join_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        user_id = request.json.get('user_id')
        game = next((g for g in games_db if g['id'] == game_id), None)
        if not game:
            return jsonify({"error": "Game not found"}), 404
        
        if user_id not in game['players']:
            game['players'].append(user_id)
        
        return jsonify({"status": "joined"})

    @app.route('/api/games/<game_id>/leave', methods=['POST', 'OPTIONS'])
    def leave_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        user_id = request.json.get('user_id')
        game = next((g for g in games_db if g['id'] == game_id), None)
        if not game:
            return jsonify({"error": "Game not found"}), 404
        
        if user_id in game['players']:
            game['players'].remove(user_id)
        
        return jsonify({"status": "left"})

def register_utility_routes(app):
    """Регистрация вспомогательных маршрутов"""
    
    @app.route('/', methods=['GET', 'OPTIONS'])
    def home():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return {"message": "Добро пожаловать в клуб настольных игр!"}

    @app.route('/api/data', methods=['GET', 'OPTIONS'])
    def get_data():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"message": "Данные успешно получены!"})

    @app.route('/api/health', methods=['GET', 'OPTIONS'])
    def health_check():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({
            "status": "ok", 
            "db": "connected" if db.session.execute("SELECT 1").scalar() else "disconnected"
        })

    @app.route('/static/js/<path:filename>', methods=['GET', 'OPTIONS'])
    def serve_js(filename):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return send_from_directory('static/js', filename, mimetype='text/javascript')

    @app.route('/static/js/modules/<path:filename>', methods=['GET', 'OPTIONS'])
    def serve_js_module(filename):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return send_from_directory('static/js/modules', filename, mimetype='application/javascript')

    @app.route('/protected', methods=['GET', 'OPTIONS'])
    @token_required
    def protected_route(user):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return {'message': f'Hello, {user.username}'}

# Вспомогательные функции
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return f(None, *args, **kwargs)
            
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

# Модели
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
