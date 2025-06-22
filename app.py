import os
import sys
import logging
from flask import Flask

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    try:
        logger.error("### 1. Начало create_app ###")
        app = Flask(__name__)
        
        @app.route("/api/test")
        def test():
            logger.error("### Вызов /api/test ###")
            return {"status": "ok"}
            
        logger.error("### 2. Приложение создано ###")
        return app
        
    except Exception as e:
        logger.error(f"!!! ОШИБКА: {str(e)} !!!")
        sys.exit(1)

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
