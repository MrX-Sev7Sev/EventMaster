from flask import current_app
import logging
from flask import Blueprint, jsonify
from app import db

data_bp = Blueprint('data', __name__, url_prefix='/api')

@data_bp.route('/data')
def get_data():
    return jsonify({"message": "Data endpoint works!"})
