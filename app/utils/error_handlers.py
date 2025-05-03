from flask import jsonify
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from jwt.exceptions import PyJWTError
from datetime import datetime

class APIError(Exception):
    """Base exception for API errors"""
    def __init__(self, message, status_code=400, error_code=None, details=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details
        self.timestamp = datetime.utcnow()

class ValidationError(APIError):
    """Raised when input validation fails"""
    def __init__(self, message, details=None):
        super().__init__(message, 400, 'VALIDATION_ERROR', details)

class AuthenticationError(APIError):
    """Raised when authentication fails"""
    def __init__(self, message, details=None):
        super().__init__(message, 401, 'AUTHENTICATION_ERROR', details)

class AuthorizationError(APIError):
    """Raised when user is not authorized"""
    def __init__(self, message, details=None):
        super().__init__(message, 403, 'AUTHORIZATION_ERROR', details)

class ResourceNotFoundError(APIError):
    """Raised when a requested resource is not found"""
    def __init__(self, message, details=None):
        super().__init__(message, 404, 'NOT_FOUND', details)

class DatabaseError(APIError):
    """Raised when database operations fail"""
    def __init__(self, message, details=None):
        super().__init__(message, 500, 'DATABASE_ERROR', details)

class TokenError(APIError):
    """Raised when token operations fail"""
    def __init__(self, message, details=None):
        super().__init__(message, 401, 'TOKEN_ERROR', details)

def register_error_handlers(app):
    """Register all error handlers with the Flask app"""
    
    @app.errorhandler(APIError)
    def handle_api_error(error):
        response = {
            'error': True,
            'message': error.message,
            'error_code': error.error_code,
            'status_code': error.status_code,
            'timestamp': error.timestamp.isoformat()
        }
        if error.details:
            response['details'] = error.details
        return jsonify(response), error.status_code

    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        response = {
            'error': True,
            'message': error.message,
            'error_code': 'VALIDATION_ERROR',
            'status_code': 400,
            'timestamp': error.timestamp.isoformat()
        }
        if error.details:
            response['details'] = error.details
        return jsonify(response), 400

    @app.errorhandler(AuthenticationError)
    def handle_auth_error(error):
        response = {
            'error': True,
            'message': error.message,
            'error_code': 'AUTHENTICATION_ERROR',
            'status_code': 401,
            'timestamp': error.timestamp.isoformat()
        }
        if error.details:
            response['details'] = error.details
        return jsonify(response), 401

    @app.errorhandler(AuthorizationError)
    def handle_authorization_error(error):
        response = {
            'error': True,
            'message': error.message,
            'error_code': 'AUTHORIZATION_ERROR',
            'status_code': 403,
            'timestamp': error.timestamp.isoformat()
        }
        if error.details:
            response['details'] = error.details
        return jsonify(response), 403

    @app.errorhandler(ResourceNotFoundError)
    def handle_not_found_error(error):
        response = {
            'error': True,
            'message': error.message,
            'error_code': 'NOT_FOUND',
            'status_code': 404,
            'timestamp': error.timestamp.isoformat()
        }
        if error.details:
            response['details'] = error.details
        return jsonify(response), 404

    @app.errorhandler(SQLAlchemyError)
    def handle_db_error(error):
        response = {
            'error': True,
            'message': 'Database operation failed',
            'error_code': 'DATABASE_ERROR',
            'status_code': 500,
            'timestamp': datetime.utcnow().isoformat()
        }
        if app.debug:
            response['details'] = str(error)
        return jsonify(response), 500

    @app.errorhandler(IntegrityError)
    def handle_integrity_error(error):
        response = {
            'error': True,
            'message': 'Database integrity error',
            'error_code': 'INTEGRITY_ERROR',
            'status_code': 400,
            'timestamp': datetime.utcnow().isoformat()
        }
        if app.debug:
            response['details'] = str(error)
        return jsonify(response), 400

    @app.errorhandler(PyJWTError)
    def handle_jwt_error(error):
        response = {
            'error': True,
            'message': 'Token validation failed',
            'error_code': 'TOKEN_ERROR',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat()
        }
        if app.debug:
            response['details'] = str(error)
        return jsonify(response), 401

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        response = {
            'error': True,
            'message': error.description,
            'error_code': 'HTTP_ERROR',
            'status_code': error.code,
            'timestamp': datetime.utcnow().isoformat()
        }
        return jsonify(response), error.code

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        response = {
            'error': True,
            'message': 'An unexpected error occurred',
            'error_code': 'INTERNAL_ERROR',
            'status_code': 500,
            'timestamp': datetime.utcnow().isoformat()
        }
        if app.debug:
            response['details'] = str(error)
        return jsonify(response), 500 