import os
from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_session import Session
from concurrent.futures import ThreadPoolExecutor
import logging

from config import get_config
from routes import register_routes
from error_handlers import register_error_handlers
from database import engine, Base
from analyzers import initialize_analyzers

def create_app():
    app = Flask(__name__)
    
    logger = logging.getLogger(__name__)    
    app.config.from_object(get_config())


    print(f"CONFIG {app.config}")

    CORS(app)
    JWTManager(app)
    Session(app)

    # Create database tables
    with app.app_context():
        Base.metadata.create_all(bind=engine)

    initialize_analyzers()

    register_routes(app)
    register_error_handlers(app)

    app.executor = ThreadPoolExecutor(max_workers=app.config['MAX_WORKERS'])

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))