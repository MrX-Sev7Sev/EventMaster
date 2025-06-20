from flask import Blueprint
from flask_jwt_extended import jwt_required, current_user
from app.models import Game
from app.models import db
from app.schemas import User, GameCreate
from app.utils import validate_request
from app.exceptions import InvalidAPIUsage

games_bp = Blueprint('games', __name__, url_prefix='/api/games')

@games_bp.route('/', methods=['POST'])
@jwt_required()
def create_game():
    """Создание новой игры"""
    try:
        game_data = GameCreate.parse_obj(validate_request(request, {
            'title': {'type': 'string', 'required': True, 'minlength': 3},
            'description': {'type': 'string', 'required': False}
        }))
        
        new_game = Game(
            title=game_data.title,
            description=game_data.description,
            owner_id=current_user.id
        )
        
        db.session.add(new_game)
        db.session.commit()
        
        return Game.from_orm(new_game).json(), 201
        
    except ValidationError as e:
        raise InvalidAPIUsage("Invalid game data", 400, {'errors': e.errors()})
