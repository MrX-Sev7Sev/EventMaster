from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from app.models import User
from app.extensions import db
from app.schemas import UserSchema
from app.exceptions import InvalidAPIUsage
from datetime import timedelta

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/signup', methods=['POST'])
def signup():
    """Регистрация нового пользователя"""
    try:
        data = request.get_json()
        if not data:
            raise InvalidAPIUsage("Требуется JSON данные", 400)

        # Проверка существующего пользователя
        if User.query.filter_by(email=data.get('email')).first():
            raise InvalidAPIUsage('Пользователь с таким email уже существует', 409)
        
        if User.query.filter_by(username=data.get('username')).first():
            raise InvalidAPIUsage('Пользователь с таким именем уже существует', 409)

        # Создание пользователя
        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=generate_password_hash(data['password'])
        )
        
        db.session.add(new_user)
        db.session.commit()

        # Токены (сроки берутся из config.py)
        access_token = create_access_token(identity=new_user.id)
        refresh_token = create_refresh_token(identity=new_user.id)
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": UserSchema().dump(new_user)
        }), 201

    except Exception as e:
        db.session.rollback()
        raise InvalidAPIUsage(str(e), 500)

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        if not data.get("email") or not data.get("password"):
            return jsonify({"error": "Email и пароль обязательны"}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Неверный email или пароль"}), 401

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.id
        }), 200

    except Exception as e:
        return jsonify({"error": "Ошибка сервера"}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  # Требуется refresh-токен
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify(access_token=new_access_token), 200
