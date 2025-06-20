from flask import current_app
from flask import Blueprint, jsonify
from app.extensions import db
import logging

data_bp = Blueprint('data', __name__, url_prefix='/api')

@data_bp.route('/data')
def get_data():
    return jsonify({"status": "success"})
