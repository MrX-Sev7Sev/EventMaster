import sys
from flask import Flask
from pathlib import Path
from app import create_app
from app import socketio

app = create_app()
sys.path.append(str(Path(__file__).parent))

app = Flask(__name__)

@app.route('/')  
def home():
    return "Привет! Это главная страница."

if __name__ == "__main__":
    app.run(debug=True)