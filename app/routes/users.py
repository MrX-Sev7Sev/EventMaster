from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, current_user, get_jwt_identity
from pydantic import ValidationError
from app.models import User
from app.extensions import db
from app.schemas import UserSchema  # Предполагается, что у вас есть схема
from app.utils import validate_request
from app.exceptions import InvalidAPIUsage

users_bp = Blueprint('users', __name__, url_prefix='/api/users')

@users_bp.route('/', methods=['GET'])
def list_users():
    return jsonify({"users": []}), 200

# Добавляем GET метод для /me
@users_bp.route('/me', methods=['GET', 'PUT'])
@jwt_required()
def handle_current_user():
    if request.method == 'GET':
        return jsonify({
            "id": current_user.id,
            "email": current_user.email,
            "username": current_user.username
        })
    
    if request.method == 'PUT':
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
            
            return jsonify({
                "id": current_user.id,
                "email": current_user.email,
                "username": current_user.username
            }), 200
            
        except ValidationError as e:
            raise InvalidAPIUsage("Invalid data format", 400, {'errors': e.errors()})
