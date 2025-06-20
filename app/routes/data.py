from flask import current_app
import logging

@data_bp.route('/data')
def get_data():
    current_app.logger.info("Обработка /api/data")  # Логируем факт вызова
    
    try:
        # Ваша бизнес-логика здесь
        result = {"status": "success", "data": []}
        current_app.logger.debug(f"Результат: {result}")  # Логируем результат
        return jsonify(result)
        
    except Exception as e:
        current_app.logger.error(f"Ошибка в /api/data: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500
