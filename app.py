from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

app = Flask(__name__)
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "https://table-games.netlify.app",  # Продакшен-домен
            ],
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True  # Если нужны куки/токены
        }
    }
)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.yourmailprovider.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mrx170vu@gmail.com'
app.config['MAIL_PASSWORD'] = 'Nn68709135'
app.config['MAIL_DEFAULT_SENDER'] = 'mrx170vu@gmail.com'

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    remember_me = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Создаем таблицы при первом запуске
with app.app_context():
    db.create_all()
    
@app.route('/api/data')
def get_data():
    return {"message": "Данные с бэкенда!"}

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['username'] = user.username
            if remember:
                user.remember_me = True
                db.session.commit()
                session.permanent = True
            return redirect(url_for('home'))
        else:
            flash('Неверное имя пользователя или пароль')
    
    return render_template('login.html')

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

@app.route('/login/mail')
def login_mail():
    # Здесь будет реализация OAuth2 авторизации через Mail.ru
    # Это примерный код, вам нужно будет использовать библиотеку для OAuth2
    # Например, authlib или requests-oauthlib
    
    # Перенаправляем пользователя на страницу авторизации Mail.ru
    auth_url = "https://oauth.mail.ru/sdk/v0.18.0/oauth.js" + \
               "response_type=code&" + \
               f"client_id=366fed0fb1a84b2b824bca35835f4ed6ф" + \
               f"redirect_uri={url_for('mail_callback', _external=True)}"
    return redirect(auth_url)

@app.route('/login/mail/callback')
def mail_callback():
    # Обработка callback от Mail.ru
    code = request.args.get('code')
    
    # Здесь нужно обменять code на access token
    # И получить данные пользователя
    
    # Примерный код:
    # token = get_mail_token(code)
    # user_info = get_mail_user_info(token)
    
    # Проверяем, есть ли пользователь в нашей базе
    # Если нет - создаем
    # Затем логиним
    
    flash('Успешный вход через Mail.ru')
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/')  
def example():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=True)
