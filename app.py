import sys
print("!!! Файл app.py начал выполняться !!!", file=sys.stderr)  # Обязательно stderr!

from flask import Flask

print("!!! Flask импортирован !!!", file=sys.stderr)

def create_app():
    print("!!! Функция create_app вызвана !!!", file=sys.stderr)
    app = Flask(__name__)
    
    @app.route("/")
    def home():
        print("!!! Обработчик / вызван !!!", file=sys.stderr)
        return {"status": "ok"}
    
    return app

app = create_app()  # Важно: создаём app в глобальной области

if __name__ == '__main__':
    print("!!! Запуск в режиме разработки !!!", file=sys.stderr)
    app.run(host='0.0.0.0', port=5000)
