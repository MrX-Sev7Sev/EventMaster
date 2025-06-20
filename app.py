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
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email уже используется')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Регистрация успешна. Теперь вы можете войти.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg = Message('Сброс пароля',
                          recipients=[email])
            msg.body = f'Для сброса пароля перейдите по ссылке: {reset_url}'
            mail.send(msg)
            
            flash('Инструкции по сбросу пароля отправлены на ваш email')
            return redirect(url_for('login'))
        else:
            flash('Email не найден')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('Ссылка для сброса пароля недействительна или просрочена')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.set_password(password)
        db.session.commit()
        
        flash('Ваш пароль был успешно изменен')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/vk-callback')
def vk_callback():
    """Обработка OAuth-колбэка от VK с использованием config.py"""
    
    # 1. Получаем код из URL
    code = request.args.get('code')
    if not code:
        flash('Ошибка: код авторизации не получен', 'error')
        return redirect(url_for('login'))

    try:
        # 2. Обмениваем код на access token (используем данные из config.py)
        vk_response = requests.get(
            Config.VK_OAUTH['TOKEN_URL'],
            params={
                'client_id': Config.VK_OAUTH['APP_ID'],
                'client_secret': Config.VK_OAUTH['APP_SECRET'],
                'redirect_uri': Config.VK_OAUTH['REDIRECT_URI'],
                'code': code
            }
        ).json()

        # 3. Проверяем наличие ошибок в ответе VK
        if 'error' in vk_response:
            error_msg = vk_response.get('error_description', 'Неизвестная ошибка VK')
            flash(f'Ошибка авторизации VK: {error_msg}', 'error')
            return redirect(url_for('login'))

        # 4. Ищем или создаем пользователя в БД
        user = User.query.filter_by(vk_id=vk_response['user_id']).first()
        if not user:
            # Получаем дополнительную информацию о пользователе
            user_info = requests.get(
                Config.VK_OAUTH['API_URL'] + 'users.get',
                params={
                    'user_ids': vk_response['user_id'],
                    'access_token': vk_response['access_token'],
                    'fields': 'photo_200,domain',
                    'v': '5.131'
                }
            ).json()
            
            user_data = user_info['response'][0]
            user = User(
                vk_id=vk_response['user_id'],
                username=user_data.get('domain'),
                full_name=f"{user_data.get('first_name')} {user_data.get('last_name')}",
                avatar=user_data.get('photo_200')
            )
            db.session.add(user)
            db.session.commit()

        # 5. Сохраняем токен
        token = UserToken(
            user_id=user.id,
            access_token=vk_response['access_token'],
            expires_at=datetime.utcnow() + timedelta(seconds=vk_response['expires_in']),
            refresh_token=vk_response.get('refresh_token')
        )
        db.session.add(token)
        db.session.commit()

        # 6. Логиним пользователя
        login_user(user)
        flash('Вы успешно вошли через VK!', 'success')

    except Exception as e:
        flash(f'Ошибка авторизации: {str(e)}', 'error')
        return redirect(url_for('login'))

    return redirect(url_for('home'))
    
@app.route('/login/mail')
def login_mail():
    """
    Перенаправление на страницу авторизации Mail.ru
    с использованием параметров из config.py
    """
    # Генерация state для защиты от CSRF
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state

    # Параметры запроса из конфига
    params = {
        'response_type': 'code',
        'client_id': app.config['MAIL_CLIENT_ID'],
        'redirect_uri': app.config['MAIL_REDIRECT_URI'],
        'scope': 'userinfo',
        'state': state
    }

    auth_url = f"{app.config['MAIL_AUTH_URL']}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/login/mail/callback')
def mail_callback():
    """
    Обработка callback от Mail.ru с использованием конфига
    """
    # Проверка обязательных параметров
    if 'code' not in request.args:
        flash('Ошибка авторизации: не получен код', 'error')
        return redirect(url_for('login'))

    # Проверка state
    if request.args.get('state') != session.pop('oauth_state', None):
        flash('Ошибка безопасности: неверный state-параметр', 'error')
        return redirect(url_for('login'))

    try:
        # Обмен кода на токен
        token_data = {
            'client_id': app.config['MAIL_CLIENT_ID'],
            'client_secret': app.config['MAIL_CLIENT_SECRET'],
            'grant_type': 'authorization_code',
            'code': request.args['code'],
            'redirect_uri': app.config['MAIL_REDIRECT_URI']
        }

        # Получение токена
        token_response = requests.post(app.config['MAIL_TOKEN_URL'], data=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()

        # Получение информации о пользователе
        user_response = requests.get(
            app.config['MAIL_USER_INFO_URL'],
            params={'access_token': token_info['access_token']}
        )
        user_response.raise_for_status()
        user_info = user_response.json()

        # Создание/обновление пользователя
        user = process_mail_user(user_info)

        # Логин пользователя (пример для Flask-Login)
        login_user(user)
        flash('Вы успешно вошли через Mail.ru!', 'success')
        return redirect(url_for('profile'))

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Mail OAuth error: {str(e)}")
        flash('Ошибка авторизации через Mail.ru', 'error')
        return redirect(url_for('login'))

def process_mail_user(user_data):
    """
    Обработка данных пользователя из Mail.ru
    """
    # Здесь должна быть ваша реализация работы с БД
    user = User.query.filter_by(mail_id=user_data.get('id')).first()
    
    if not user:
        user = User(
            mail_id=user_data.get('id'),
            email=user_data.get('email'),
            name=user_data.get('name'),
            avatar=user_data.get('image')
        )
        db.session.add(user)
    else:
        user.email = user_data.get('email', user.email)
        user.avatar = user_data.get('image', user.avatar)
    
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
