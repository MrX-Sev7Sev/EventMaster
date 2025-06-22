from app import create_app
from app.extensions import db
from flask_migrate import Migrate

app = create_app()
migrate = Migrate(app, db)
