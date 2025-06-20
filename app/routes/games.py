from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from app.models import Game
from app.extensions import db

games_bp = Blueprint('games', __name__, url_prefix='/api/games')

@games_bp.route('/games')
def get_games():
    games = Game.query.all()
    return {'games': [game.to_dict() for game in games]}

@games_bp.route('/', methods=['GET'])
def get_games():
    games = Game.query.all()
    return jsonify([game.to_dict() for game in games]), 200

@games_bp.route('/<int:game_id>', methods=['GET'])
def get_game(game_id):
    game = Game.query.get_or_404(game_id)
    return jsonify(game.to_dict()), 200

@games_bp.route('/<int:game_id>/join', methods=['POST'])
@jwt_required()
def join_game(game_id):
    user_id = get_jwt_identity()
    game = Game.query.get_or_404(game_id)
    game.players.append(user_id)
    db.session.commit()
    return jsonify({"message": "Joined the game!"}), 200
