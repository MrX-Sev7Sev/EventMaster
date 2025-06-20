from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, db
from .schemas import UserSchema
from flask_jwt_extended import create_access_token
from .utils import validate_request
from .exceptions import InvalidAPIUsage

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/signup', methods=['POST'])
def signup():
    # Валидация входных данных
    data = validate_request(request, {
        'username': {'type': 'string', 'required': True, 'minlength': 3},
        'email': {'type': 'string', 'required': True, 'regex': 'email'},
        'password': {'type': 'string', 'required': True, 'minlength': 6}
    })

    # Проверка существующего пользователя
    if User.query.filter_by(email=data['email']).first():
        raise InvalidAPIUsage('User with this email already exists', 400)
    
    if User.query.filter_by(username=data['username']).first():
        raise InvalidAPIUsage('User with this username already exists', 400)

    # Создание нового пользователя
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password'])
    )
    
    db.session.add(new_user)
    db.session.commit()

    # Создание токена для нового пользователя
    access_token = create_access_token(identity=new_user.id)
    
    return jsonify({
        "message": "User created successfully",
        "user": UserSchema().dump(new_user),
        "token": access_token
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    # Валидация входных данных
    data = validate_request(request, {
        'email': {'type': 'string', 'required': True},
        'password': {'type': 'string', 'required': True}
    })

    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        raise InvalidAPIUsage("Invalid email or password", 401)
    
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        "token": access_token,
        "user": UserSchema().dump(user)
    }), 200
