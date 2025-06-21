from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token
from app.models import User
from app.extensions import db  # Новый импорт
from app.schemas import UserSchema
from app.utils import validate_request
from app.exceptions import InvalidAPIUsage
from datetime import timedelta
from flask_cors import CORS
from flask_cors import cross_origin
from app.utils import validate_request

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
CORS(auth_bp)

@auth_bp.route('/test')
def test():
    return "Works!", 200
@auth_bp.route('/login', methods=['GET'])
def login_test():
    return "Сервер работает! Используйте POST для входа", 200
@auth_bp.route('/signup', methods=['POST'])
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

@auth_bp.route('/login', methods=['POST'])
@cross_origin()
def login():
    data = request.get_json()
    if not validate_request(request.json, ['email', 'password']):
    return {"error": "Invalid data"}, 400
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Требуется JSON данные"}), 400

        # Добавьте логирование для диагностики
        print("Полученные данные:", data)
        
        email = data.get("email")
        password = data.get("password")
        
        if not email or not password:
            return jsonify({"error": "Email и пароль обязательны"}), 400

        # ... ваш код аутентификации ...

    except Exception as e:
        # Логируем ошибку
        print("Ошибка в /login:", str(e))
        return jsonify({"error": "Internal Server Error"}), 500

    except Exception as e:
        raise InvalidAPIUsage(str(e), 500)
