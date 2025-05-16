from flask import Blueprint, render_template, url_for, redirect, flash, request
from flask_login import login_user, current_user, logout_user, login_required
from app import db, mail 
from app.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm
from app.models import User, PasswordResetToken
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from datetime import datetime, timedelta
import secrets
import requests

auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.game'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember_me.data)
            
            if form.remember_me.data:
                user.remember_me = True
                db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.game'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.game'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html', title='Register', form=form)

@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.game'))
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html', title='Reset Password', form=form)

@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.game'))
    
    token_data = PasswordResetToken.query.filter_by(token=token).first()
    if not token_data or token_data.used or token_data.expires_at < datetime.utcnow():
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('auth.reset_password_request'))
    
    user = token_data.user
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        token_data.used = True
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html', title='Reset Password', form=form)

@auth.route('/auth/vk')
def vk_auth():
    vk_auth_url = f"https://oauth.vk.com/authorize?client_id={current_app.config['VK_APP_ID']}&display=page&redirect_uri={current_app.config['VK_REDIRECT_URI']}&response_type=code&v=5.131"
    return redirect(vk_auth_url)

@auth.route('/auth/vk/callback')
def vk_callback():
    code = request.args.get('code')
    if not code:
        flash('Authorization failed', 'danger')
        return redirect(url_for('auth.login'))
    
    # Exchange code for access token
    token_url = f"https://oauth.vk.com/access_token?client_id={current_app.config['VK_APP_ID']}&client_secret={current_app.config['VK_APP_SECRET']}&redirect_uri={current_app.config['VK_REDIRECT_URI']}&code={code}"
    response = requests.get(token_url)
    data = response.json()
    
    if 'error' in data:
        flash('VK authorization failed', 'danger')
        return redirect(url_for('auth.login'))
    
    vk_id = data.get('user_id')
    email = data.get('email')
    
    # Check if user already exists
    user = User.query.filter((User.vk_id == vk_id) | (User.email == email)).first()
    
    if not user:
        # Create new user
        username = f"vk_{vk_id}"
        user = User(username=username, email=email, vk_id=vk_id, password=generate_password_hash(secrets.token_hex(16)))
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('main.game'))

@main.route('/game')
@login_required
def game():
    return render_template('game.html', title='Game')

def send_password_reset_email(user):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.session.add(reset_token)
    db.session.commit()
    
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    
    msg = Message('Password Reset Request',
                  sender='noreply@yourdomain.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)