import logging
from flask import jsonify
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_exception(e):
        logger.error(f"HTTP error occurred: {str(e)}")
        return jsonify({"error": str(e)}), e.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        logger.exception("An unexpected error occurred")
        return jsonify({"error": "An unexpected error occurred"}), 500