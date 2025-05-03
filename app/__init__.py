import os
from flask import Flask, jsonify, request, Response, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flasgger import Swagger
from flask_cors import CORS
import time
from app.config import Config
from app.utils.error_handlers import register_error_handlers
from datetime import datetime
from werkzeug.exceptions import HTTPException
import secrets

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()

# Dictionary to track request counts for rate limiting
request_counts = {}
# How many requests allowed within the time window
RATE_LIMIT = 15
# Time window in seconds
RATE_LIMIT_WINDOW = 60

def create_app(config_class=Config):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    # Enable CORS for all routes
    CORS(app, supports_credentials=True)

    # Initialize Swagger for API documentation
    swagger = Swagger(app, template_file=os.path.join(os.path.dirname(__file__), 'swagger.yaml'))
    
    # Default configuration
    app.config.from_object(config_class)
    
    # Enable debug mode
    app.debug = True

    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    
    # Register error handlers
    register_error_handlers(app)

    # Configure JWT handling
    @jwt.user_identity_loader
    def user_identity_lookup(identity):
        try:
            return str(identity)
        except Exception:
            return None
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        try:
            identity = jwt_data.get("sub")
            if not identity:
                return None
                
            user_id = int(identity)
            from app.models.user import User
            user = User.query.filter_by(id=user_id).one_or_none()
            return user
        except (ValueError, TypeError, Exception):
            return None
    
    # JWT Error Handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': True,
            'message': 'Token has expired',
            'error_code': 'TOKEN_EXPIRED',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'expired_at': jwt_payload.get('exp'),
                'current_time': int(time.time())
            }
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': True,
            'message': 'Invalid token',
            'error_code': 'INVALID_TOKEN',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': str(error)
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': True,
            'message': 'Missing token',
            'error_code': 'MISSING_TOKEN',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': str(error)
        }), 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': True,
            'message': 'Fresh token required',
            'error_code': 'FRESH_TOKEN_REQUIRED',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'token_type': jwt_payload.get('type', 'unknown'),
                'token_expiry': jwt_payload.get('exp')
            }
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': True,
            'message': 'Token has been revoked',
            'error_code': 'TOKEN_REVOKED',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'token_id': jwt_payload.get('jti'),
                'revoked_at': jwt_payload.get('revoked_at')
            }
        }), 401
    
    # Global error handler
    @app.errorhandler(Exception)
    def handle_error(error):
        if isinstance(error, HTTPException):
            response = {
                'error': True,
                'message': error.description,
                'error_code': error.name,
                'status_code': error.code,
                'timestamp': datetime.utcnow().isoformat()
            }
            return jsonify(response), error.code
            
        # Handle unexpected errors
        response = {
            'error': True,
            'message': 'An unexpected error occurred',
            'error_code': 'INTERNAL_SERVER_ERROR',
            'status_code': 500,
            'timestamp': datetime.utcnow().isoformat()
        }
        if app.debug:
            response['details'] = str(error)
        return jsonify(response), 500

    # In testing mode, make token expiration predictable
    if app.config.get('TESTING'):
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1  # 1 second for tests

    # Add security headers
    @app.after_request
    def add_security_headers(response):
        # Skip Swagger UI routes
        if request.path.startswith('/apidocs') or request.path.startswith('/flasgger_static'):
            return response

        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response
    
    # Implement rate limiting
    @app.before_request
    def rate_limiting():
        # Skip rate limiting in test mode
        if app.config.get('TESTING'):
            return
        
        # Skip rate limiting for non-auth endpoints
        if not request.path.startswith('/api/auth') and not request.path.startswith('/api/login'):
            return
        
        # Get the client IP
        client_ip = request.remote_addr
        current_time = time.time()
        
        # Clean up old requests
        for ip in list(request_counts.keys()):
            request_counts[ip] = [req_time for req_time in request_counts[ip] 
                                  if current_time - req_time < RATE_LIMIT_WINDOW]
            if not request_counts[ip]:
                del request_counts[ip]
        
        # Check current request count
        if client_ip in request_counts and len(request_counts[client_ip]) >= RATE_LIMIT:
            return jsonify({
                'error': True,
                'message': 'Too many requests, please try again later',
                'error_code': 'RATE_LIMIT_EXCEEDED',
                'status_code': 429,
                'timestamp': datetime.utcnow().isoformat(),
                'details': {
                    'retry_after': RATE_LIMIT_WINDOW
                }
            }), 429
        
        # Add current request
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        request_counts[client_ip].append(current_time)

    # Add CSRF protection
    @app.before_request
    def csrf_protect():
        # Skip CSRF check for GET requests and Swagger UI
        if request.method == "GET" or request.path.startswith('/apidocs'):
            return
            
        # Skip CSRF check in test mode
        if app.config.get('TESTING'):
            return
            
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            # Generate CSRF token if not exists
            if 'csrf_token' not in session:
                session['csrf_token'] = secrets.token_hex(32)
                
            token = request.headers.get('X-CSRF-Token')
            if not token or token != session.get('csrf_token'):
                return jsonify({
                    'error': True,
                    'message': 'Invalid CSRF token',
                    'error_code': 'INVALID_CSRF_TOKEN',
                    'status_code': 403,
                    'timestamp': datetime.utcnow().isoformat()
                }), 403

    # Register models
    from app.models import user, account, transaction

    # Register blueprints
    from app.routes import auth, accounts, transactions
    app.register_blueprint(auth.bp)
    app.register_blueprint(accounts.bp)
    app.register_blueprint(transactions.bp)
    
    # Root endpoint for testing
    @app.route('/')
    def home():
        return jsonify({
            'message': "Welcome to the Banking API",
            'version': '1.0.0',
            'status': 'operational'
        })

    # CLI commands
    @app.cli.command('init-db')
    def init_db_command():
        """Clear the existing data and create new tables."""
        db.drop_all()
        db.create_all()
        print('Initialized the database.')

    return app 