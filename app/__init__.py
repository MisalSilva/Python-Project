import os
from flask import Flask, jsonify, request, Response
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
    CORS(app)

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
        return str(identity)
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        try:
            user_id = int(identity)
            from app.models.user import User
            user = User.query.filter_by(id=user_id).one_or_none()
            if not user:
                return None
            return user
        except (ValueError, TypeError):
            return None
    
    # JWT Error Handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {
            'error': True,
            'message': 'Token has expired',
            'error_code': 'TOKEN_EXPIRED',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'expired_at': jwt_payload.get('exp'),
                'current_time': int(time.time())
            }
        }, 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {
            'error': True,
            'message': 'Invalid token',
            'error_code': 'INVALID_TOKEN',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': str(error)
        }, 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return {
            'error': True,
            'message': 'Missing token',
            'error_code': 'MISSING_TOKEN',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': str(error)
        }, 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return {
            'error': True,
            'message': 'Fresh token required',
            'error_code': 'FRESH_TOKEN_REQUIRED',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'token_type': jwt_payload.get('type', 'unknown'),
                'token_expiry': jwt_payload.get('exp')
            }
        }, 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return {
            'error': True,
            'message': 'Token has been revoked',
            'error_code': 'TOKEN_REVOKED',
            'status_code': 401,
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'token_id': jwt_payload.get('jti'),
                'revoked_at': jwt_payload.get('revoked_at')
            }
        }, 401
    
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
            return jsonify({"error": "Too many requests, please try again later"}), 429
        
        # Add current request
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        request_counts[client_ip].append(current_time)

    # Add CSRF protection
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = request.headers.get('X-CSRF-Token')
            if not token or token != session.get('csrf_token'):
                return jsonify({"error": "Invalid CSRF token"}), 403

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
        return jsonify({"message": "Welcome to the Banking API"})

    # CLI commands
    @app.cli.command('init-db')
    def init_db_command():
        """Clear the existing data and create new tables."""
        db.drop_all()
        db.create_all()
        print('Initialized the database.')

    return app 