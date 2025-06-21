from flask import Blueprint, jsonify, current_app
from app.extensions import db
from sqlalchemy import text, inspect
import logging

data_bp = Blueprint('data', __name__, url_prefix='/api')
test_bp = Blueprint('test', __name__, url_prefix='/api')

@data_bp.route('/data')
def get_data():
    return jsonify({"status": "success"})

@test_bp.route('/test-db')
def test_db():
    try:
        # 1. Проверяем подключение к БД
        result = db.session.execute(text("SELECT 1")).scalar()
        
        # 2. Получаем список таблиц (совместимо с SQLAlchemy 2.0+)
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # 3. Проверяем наличие обязательных таблиц
        required_tables = {'users', 'games', 'token_blocklist'}
        missing_tables = required_tables - set(tables)
        
        # 4. Проверяем количество записей в основных таблицах
        counts = {}
        for table in ['users', 'games']:
            if table in tables:
                counts[f"{table}_count"] = db.session.execute(
                    text(f"SELECT COUNT(*) FROM {table}")
                ).scalar()
        
        return jsonify({
            "status": "success",
            "db_connection": "OK",
            "tables": tables,
            "missing_tables": list(missing_tables),
            "counts": counts,
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
