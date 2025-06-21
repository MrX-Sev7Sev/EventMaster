from flask import current_app
from flask import Blueprint, jsonify
from app.extensions import db
import logging

data_bp = Blueprint('data', __name__, url_prefix='/api')
test_bp = Blueprint('test', __name__, url_prefix='/api')

@data_bp.route('/data')
def get_data():
    return jsonify({"status": "success"})

@test_bp.route('/test-db')
def test_db():
    try:
        # Используйте text() для сырых SQL-запросов
        from sqlalchemy import text
        result = db.session.execute(text("SELECT 1")).scalar()
        return jsonify({"db": "OK"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
