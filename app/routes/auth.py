from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token
from app.models import User, db
from app.schemas import UserSchema
from app.utils import validate_request
from app.exceptions import InvalidAPIUsage
from datetime import timedelta

users_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@users_bp.route('/signup', methods=['POST'])
def signup():
    """Регистрация нового пользователя"""
    try:
        # Валидация входных данных
        data = validate_request(request, {
            'username': {'type': 'string', 'required': True, 'minlength': 3, 'maxlength': 50},
            'email': {'type': 'string', 'required': True, 'regex': 'email'},
            'password': {'type': 'string', 'required': True, 'minlength': 8}
        })

        # Проверка существующего пользователя
        if User.query.filter_by(email=data['email']).first():
            raise InvalidAPIUsage('User with this email already exists', 409)
        
        if User.query.filter_by(username=data['username']).first():
            raise InvalidAPIUsage('User with this username already exists', 409)

        # Создание нового пользователя
        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=generate_password_hash(data['password'])
        )
        
        db.session.add(new_user)
        db.session.commit()

        # Создание токенов
        access_token = create_access_token(
            identity=new_user.id,
            expires_delta=timedelta(minutes=30)
        )
        refresh_token = create_refresh_token(
            identity=new_user.id,
            expires_delta=timedelta(days=7)
        )
        
        return jsonify({
            "message": "User created successfully",
            "user": UserSchema().dump(new_user),
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 201

    except Exception as e:
        db.session.rollback()
        raise InvalidAPIUsage(str(e), 500)

@users_bp.route('/login', methods=['POST'])
def login():
    """Аутентификация пользователя"""
    try:
        # Валидация входных данных
        data = validate_request(request, {
            'email': {'type': 'string', 'required': True},
            'password': {'type': 'string', 'required': True}
        })

        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not check_password_hash(user.password_hash, data['password']):
            raise InvalidAPIUsage("Invalid email or password", 401)
        
        # Создание токенов
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(minutes=30)
        )
        refresh_token = create_refresh_token(
            identity=user.id,
            expires_delta=timedelta(days=7)
        )
        
        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": UserSchema().dump(user)
        }), 200

    except Exception as e:
        raise InvalidAPIUsage(str(e), 500)
