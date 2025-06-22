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
from config import config  # Импортируем исправленный config
import os
import logging

# Инициализация расширений
db = SQLAlchemy()
mail = Mail()
serializer = None

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
    tokens = db.relationship('UserToken', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    api_token = db.Column(db.String(500))
    access_token = db.Column(db.String(500))
    expires_at = db.Column(db.DateTime)
    refresh_token = db.Column(db.String(500))

def create_app():
    app = Flask(__name__)

    app.config.update(
        # Базовые настройки
        SECRET_KEY=config.SECRET_KEY,
        FLASK_ENV=config.FLASK_ENV,
        
        # Настройки базы данных
        SQLALCHEMY_DATABASE_URI=config.SQLALCHEMY_DATABASE_URI,
        SQLALCHEMY_TRACK_MODIFICATIONS=config.SQLALCHEMY_TRACK_MODIFICATIONS,
        SQLALCHEMY_ENGINE_OPTIONS=config.SQLALCHEMY_ENGINE_OPTIONS,
        
        # Настройки аутентификации
        JWT_SECRET_KEY=config.JWT_SECRET_KEY,
        JWT_ACCESS_TOKEN_EXPIRES=config.JWT_ACCESS_TOKEN_EXPIRES,
        JWT_REFRESH_TOKEN_EXPIRES=config.JWT_REFRESH_TOKEN_EXPIRES,
        
        # Настройки CORS
        CORS_ORIGINS=config.CORS_ORIGINS,
        CORS_SUPPORTS_CREDENTIALS=config.CORS_SUPPORTS_CREDENTIALS,
        CORS_METHODS=config.CORS_METHODS,
        CORS_ALLOW_HEADERS=config.CORS_ALLOW_HEADERS,
        
        # Настройки почты
        MAIL_SERVER=config.MAIL_SERVER,
        MAIL_PORT=config.MAIL_PORT,
        MAIL_USE_SSL=config.MAIL_USE_SSL,
        MAIL_USERNAME=config.MAIL_USERNAME,
        MAIL_PASSWORD=config.MAIL_PASSWORD,
        MAIL_DEFAULT_SENDER=config.MAIL_DEFAULT_SENDER,
        
        # OAuth Mail.ru
        MAIL_CLIENT_ID=config.MAIL_CLIENT_ID,
        MAIL_CLIENT_SECRET=config.MAIL_CLIENT_SECRET,
        MAIL_REDIRECT_URI=config.MAIL_REDIRECT_URI,
        MAIL_AUTH_URL=config.MAIL_AUTH_URL,
        MAIL_TOKEN_URL=config.MAIL_TOKEN_URL,
        MAIL_USER_INFO_URL=config.MAIL_USER_INFO_URL,
        
        # Настройки сериализатора
        SERIALIZER_SECRET_KEY=config.SERIALIZER_SECRET_KEY,
        SERIALIZER_SALT=config.SERIALIZER_SALT
    )

    # Настройка логирования
    if app.config['FLASK_ENV'] == 'production':
        gunicorn_logger = logging.getLogger('gunicorn.error')
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.setLevel(gunicorn_logger.level)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Инициализация расширений
    from flask_sqlalchemy import SQLAlchemy
    from flask_mail import Mail

    db = SQLAlchemy()
    mail = Mail()

    db.init_app(app)
    mail.init_app(app)
    
    global serializer
    serializer = URLSafeTimedSerializer(
        app.config['SERIALIZER_SECRET_KEY'],
        salt=app.config['SERIALIZER_SALT']
    )
    
    # Настройка CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "supports_credentials": True,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    @app.route('/api/ping')
    def ping():
        return jsonify({"status": "ok", "message": "pong"})
    
    @app.route('/api/test')
    def test():
        return jsonify({
            "status": "ok",
            "routes": [str(rule) for rule in app.url_map.iter_rules()],
            "env": {
                "FLASK_ENV": os.getenv("FLASK_ENV"),
                "DATABASE_URL": "OK" if os.getenv("DATABASE_URL") else "MISSING"
            }
        })

    @app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
    def login():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        
        if not user or not user.check_password(data.get('password')):
            return jsonify({"error": "Invalid credentials"}), 401
            
        token = generate_jwt(user.id)
        
        user_token = UserToken(
            user_id=user.id,
            api_token=token,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(user_token)
        db.session.commit()
        
        return jsonify({
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "access_token": token
        })

    @app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
    def register():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"error": "Email and password required"}), 400
            
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "User exists"}), 400
            
        user = User(
            email=data['email'],
            username=data.get('username', data['email'].split('@')[0]),
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        
        return jsonify({"id": user.id}), 201

    @app.route('/api/get-test-token', methods=['GET'])
    def get_test_token():
        try:
            user = User.query.filter_by(email="test@example.com").first()
            
            if not user:
                user = User(
                    email="test@example.com",
                    username="test_user"
                )
                user.set_password("12345")
                db.session.add(user)
                db.session.commit()
            
            token = generate_jwt(user.id)
            
            user_token = UserToken(
                user_id=user.id,
                api_token=token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            db.session.add(user_token)
            db.session.commit()
            
            return jsonify({"token": token})
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/auth/mail', methods=['GET', 'OPTIONS'])
    def start_mail_oauth():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
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

    @app.route('/api/users/me', methods=['GET', 'OPTIONS'])
    def get_current_user():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401
        
        try:
            token = auth_header.split()[1]
        except IndexError:
            return jsonify({"error": "Invalid token format"}), 401
        
        user_token = UserToken.query.filter_by(api_token=token).first()
        if not user_token or user_token.expires_at < datetime.utcnow():
            return jsonify({"error": "Invalid or expired token"}), 401
        
        return jsonify({
            "id": user_token.user.id,
            "email": user_token.user.email,
            "username": user_token.user.username
        })

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

    @app.route('/api/games', methods=['GET', 'OPTIONS'])
    def get_games():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"games": []})

    @app.route('/api/games', methods=['POST', 'OPTIONS'])
    def create_game():
        if request.method == 'OPTIONS':
            return jsonify(), 200
            
        game = request.json
        game['id'] = "1"
        return jsonify({"id": game['id']}), 201

    @app.route('/api/games/<game_id>', methods=['DELETE', 'OPTIONS'])
    def delete_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"status": "deleted"})

    @app.route('/api/games/<game_id>', methods=['PUT', 'OPTIONS'])
    def update_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"status": "updated"})

    @app.route('/api/games/<game_id>/join', methods=['POST', 'OPTIONS'])
    def join_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"status": "joined"})

    @app.route('/api/games/<game_id>/leave', methods=['POST', 'OPTIONS'])
    def leave_game(game_id):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({"status": "left"})

    @app.route('/', methods=['GET', 'OPTIONS'])
    def home():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return {"message": "Добро пожаловать в клуб настольных игр!"}

    @app.route('/api/health', methods=['GET', 'OPTIONS'])
    def health_check():
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return jsonify({
            "status": "ok", 
            "db": "connected" if db.session.execute("SELECT 1").scalar() else "disconnected"
        })

    @app.route('/protected', methods=['GET', 'OPTIONS'])
    @token_required
    def protected_route(user):
        if request.method == 'OPTIONS':
            return jsonify(), 200
        return {'message': f'Hello, {user.username}'}

    # Создание таблиц
    with app.app_context():
        db.create_all(
        app.logger.info("Registered routes:")
        for rule in app.url_map.iter_rules():
            app.logger.info(f"{rule}")
    
    return app

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
    return f"generated-jwt-for-{user_id}"

app = create_app()

def wsgi_app(environ, start_response):
    return app(environ, start_response)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
