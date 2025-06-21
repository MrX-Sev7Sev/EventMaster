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
        from sqlalchemy import text
        from flask import current_app
        
        # 1. Проверяем подключение
        result = db.session.execute(text("SELECT 1")).scalar()
        
        # 2. Получаем список таблиц
        tables = db.engine.table_names()
        
        # 3. Проверяем конфигурацию
        return jsonify({
            "status": "success",
            "db_connection": "OK",
            "tables": tables,
            "db_config": {
                "db_url": current_app.config['SQLALCHEMY_DATABASE_URI'],
                "ssl_mode": current_app.config['SQLALCHEMY_ENGINE_OPTIONS']['connect_args']['sslmode']
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error_type": type(e).__name__,
            "details": str(e),
            "db_config": {
                "db_url": current_app.config.get('SQLALCHEMY_DATABASE_URI'),
                "ssl_mode": current_app.config.get('SQLALCHEMY_ENGINE_OPTIONS', {}).get('connect_args', {}).get('sslmode')
            }
        }), 500
