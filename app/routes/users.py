from flask import Blueprint, request
from flask_jwt_extended import jwt_required, current_user
from pydantic import ValidationError
from app.models import User
from app.extensions import db  # Новый импорт
from app.schemas import User
from app.utils import validate_request
from app.exceptions import InvalidAPIUsage

users_bp = Blueprint('users', __name__, url_prefix='/api/users')

@users_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Получение данных текущего пользователя"""
    try:
        user_data = User.from_orm(current_user)
        return user_data.json(), 200
    except Exception as e:
        raise InvalidAPIUsage(str(e), 500)

@users_bp.route('/me', methods=['PUT'])
@jwt_required()
def update_user():
    """Обновление данных пользователя"""
    try:
        data = validate_request(request, {
            'username': {'type': 'string', 'required': False, 'minlength': 3},
            'avatar': {'type': 'string', 'required': False}
        })
        
        if 'username' in data:
            existing_user = User.query.filter(
                User.username == data['username'],
                User.id != current_user.id
            ).first()
            if existing_user:
                raise InvalidAPIUsage("Username already taken", 400)
            current_user.username = data['username']
        
        if 'avatar' in data:
            current_user.avatar = data['avatar']
        
        db.session.commit()
        
        return User.from_orm(current_user).json(), 200
        
    except ValidationError as e:
        raise InvalidAPIUsage("Invalid data format", 400, {'errors': e.errors()})
