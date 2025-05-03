from flask import Blueprint, request, jsonify, current_app, session
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
    get_jwt_header,
)
from datetime import datetime, timedelta
from app import db, jwt
from app.models.user import User
from app.models.token_blocklist import TokenBlocklist
from app.utils.validators import (
    validate_email, validate_password, validate_username,
    validate_name
)
from app.utils.error_handlers import (
    ValidationError, AuthenticationError, ResourceNotFoundError,
    TokenError, DatabaseError
)
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import json

bp = Blueprint("auth", __name__, url_prefix="/api")

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Callback function to check if a JWT exists in the database blocklist"""
    try:
        jti = jwt_payload.get("jti")
        if not jti:
            return True  # Consider tokens without JTI as revoked
        return TokenBlocklist.is_jti_revoked(jti)
    except Exception:
        return True  # Consider tokens with errors as revoked

def validate_json_request():
    """Validate that the request contains valid JSON data"""
    if not request.is_json:
        raise ValidationError('Request must contain JSON data')
    
    try:
        data = request.get_json()
        if not data:
            raise ValidationError('No data provided')
        return data
    except json.JSONDecodeError:
        raise ValidationError('Invalid JSON data')

@bp.route("/register", methods=["POST"])
@bp.route("/auth/register", methods=["POST"])
def register():
    try:
        data = validate_json_request()
        
        # Validate required fields
        required_fields = ['email', 'password', 'username', 'first_name', 'last_name']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            raise ValidationError(
                f"Missing required fields: {', '.join(missing_fields)}",
                details={'missing_fields': missing_fields}
            )
        
        # Validate email format
        if not validate_email(data['email']):
            raise ValidationError(
                'Invalid email format. Please use a valid Gmail address (e.g., username@gmail.com). '
                'Gmail addresses must be 6-30 characters long and can only contain letters, numbers, dots, and underscores.'
            )
        
        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            raise ValidationError('Email already registered')
        
        # Validate username
        if not validate_username(data['username']):
            raise ValidationError(
                'Invalid username format. Username must be 3-50 characters long, start with a letter, '
                'and can only contain letters, numbers, underscores, and hyphens.'
            )
        
        # Check if username already exists
        if User.query.filter_by(username=data['username']).first():
            raise ValidationError('Username already taken')
        
        # Validate password
        if not validate_password(data['password']):
            raise ValidationError(
                'Password must be 8-128 characters long and contain at least one uppercase letter, '
                'one lowercase letter, one number, and one special character.'
            )
        
        # Validate names
        if not validate_name(data['first_name']):
            raise ValidationError(
                'First name must be 2-50 characters long and can only contain letters, spaces, hyphens, and apostrophes.'
            )
        
        if not validate_name(data['last_name']):
            raise ValidationError(
                'Last name must be 2-50 characters long and can only contain letters, spaces, hyphens, and apostrophes.'
            )
        
        # Create new user
        new_user = User(
            email=data['email'],
            username=data['username'],
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        new_user.set_password(data['password'])
        
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise ValidationError('User with this email or username already exists')
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError('Failed to create user account', details=str(e))
        
        # Create initial tokens
        try:
            access_token = create_access_token(
                identity=new_user.id,
                additional_claims={
                    'role': new_user.role,
                    'username': new_user.username,
                    'email': new_user.email
                },
                fresh=True
            )
            refresh_token = create_refresh_token(
                identity=new_user.id,
                additional_claims={
                    'role': new_user.role,
                    'username': new_user.username,
                    'email': new_user.email
                }
            )
        except Exception as e:
            raise TokenError('Failed to create authentication tokens', details=str(e))
        
        return jsonify({
            'message': 'Registration successful',
            'user': new_user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except (ValidationError, DatabaseError, TokenError) as e:
        raise e
    except Exception as e:
        raise DatabaseError('Failed to create user account', details=str(e))

@bp.route("/login", methods=["POST"])
@bp.route("/auth/login", methods=["POST"])
def login():
    try:
        data = validate_json_request()
        
        # Check if using email or username
        if "email" in data and "password" in data:
            user = User.query.filter_by(email=data["email"]).first()
        elif "username" in data and "password" in data:
            user = User.query.filter_by(username=data["username"]).first()
        else:
            raise ValidationError('Email/username and password are required')
        
        # Verify user exists and password is correct
        if not user or not user.check_password(data["password"]):
            raise AuthenticationError('Invalid credentials')
        
        # Include only necessary claims in JWT
        additional_claims = {
            'role': user.role,
            'username': user.username,
            'email': user.email
        }
        
        try:
            # Create access token and refresh token
            access_token = create_access_token(
                identity=user.id,
                additional_claims=additional_claims,
                fresh=True
            )
            refresh_token = create_refresh_token(
                identity=user.id,
                additional_claims=additional_claims
            )
        except Exception as e:
            raise TokenError('Failed to create authentication tokens', details=str(e))
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        })
        
    except (ValidationError, AuthenticationError, TokenError) as e:
        raise e
    except Exception as e:
        raise DatabaseError('Login failed', details=str(e))

@bp.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            raise TokenError('Invalid token identity')
        
        user = User.query.get(int(current_user_id))
        if not user:
            raise ResourceNotFoundError('User not found')
        
        # Get the current refresh token
        current_token = get_jwt()
        
        try:
            # Revoke the current refresh token
            TokenBlocklist.revoke_token(
                jti=current_token['jti'],
                expires_at=datetime.fromtimestamp(current_token['exp']),
                token_type='refresh',
                user_id=user.id
            )
        except Exception as e:
            raise TokenError('Failed to revoke refresh token', details=str(e))
        
        # Create new tokens
        additional_claims = {
            'role': user.role,
            'username': user.username,
            'email': user.email
        }
        
        try:
            new_access_token = create_access_token(
                identity=current_user_id,
                additional_claims=additional_claims,
                fresh=True
            )
            new_refresh_token = create_refresh_token(
                identity=current_user_id,
                additional_claims=additional_claims
            )
        except Exception as e:
            raise TokenError('Failed to create new tokens', details=str(e))
        
        return jsonify({
            'access_token': new_access_token,
            'refresh_token': new_refresh_token
        })
        
    except (TokenError, ResourceNotFoundError) as e:
        raise e
    except Exception as e:
        raise DatabaseError('Token refresh failed', details=str(e))

@bp.route("/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    try:
        # Get the current token
        current_token = get_jwt()
        user_id = get_jwt_identity()
        
        if not user_id:
            raise TokenError('Invalid token identity')
        
        try:
            # Add both access and refresh tokens to blocklist
            TokenBlocklist.revoke_token(
                jti=current_token['jti'],
                expires_at=datetime.fromtimestamp(current_token['exp']),
                token_type='access',
                user_id=user_id
            )
            
            # If there's a refresh token in the request, revoke it too
            refresh_token = get_jwt_header().get('refresh_token')
            if refresh_token:
                TokenBlocklist.revoke_token(
                    jti=refresh_token['jti'],
                    expires_at=datetime.fromtimestamp(refresh_token['exp']),
                    token_type='refresh',
                    user_id=user_id
                )
        except Exception as e:
            raise TokenError('Failed to revoke tokens', details=str(e))
        
        return jsonify({"message": "Successfully logged out"})
        
    except TokenError as e:
        raise e
    except Exception as e:
        raise DatabaseError('Logout failed', details=str(e))

@bp.route("/auth/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            raise TokenError('Invalid token identity')
            
        user = User.query.get(int(current_user_id))
        
        if not user:
            raise ResourceNotFoundError('User not found')
        
        return jsonify(user.to_dict())
        
    except (TokenError, ResourceNotFoundError) as e:
        raise e
    except Exception as e:
        raise DatabaseError('Failed to retrieve user profile', details=str(e))

@bp.route("/auth/verify", methods=["POST"])
@jwt_required()
def verify_token():
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            raise TokenError('Invalid token identity')
            
        user = User.query.get(int(current_user_id))
        
        if not user:
            raise ResourceNotFoundError('User not found')
        
        # Get token information
        token = get_jwt()
        
        # Verify token is not revoked
        if TokenBlocklist.is_jti_revoked(token['jti']):
            raise TokenError('Token has been revoked')
        
        return jsonify({
            'message': 'Token is valid',
            'verified': True,
            'user': user.to_dict(),
            'token_info': {
                'expires_at': datetime.fromtimestamp(token['exp']).isoformat(),
                'token_type': token.get('type', 'access'),
                'is_fresh': token.get('fresh', False),
                'claims': {
                    'role': token.get('role'),
                    'username': token.get('username'),
                    'email': token.get('email')
                }
            }
        })
        
    except (TokenError, ResourceNotFoundError) as e:
        raise e
    except Exception as e:
        raise DatabaseError('Token verification failed', details=str(e))

@bp.route("/auth/change-password", methods=["POST"])
@jwt_required(fresh=True)
def change_password():
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            raise TokenError('Invalid token identity')
            
        user = User.query.get(int(current_user_id))
        
        if not user:
            raise ResourceNotFoundError('User not found')
        
        data = validate_json_request()
        
        # Validate required fields
        if not all(k in data for k in ("current_password", "new_password")):
            raise ValidationError('Current password and new password are required')
        
        # Verify current password
        if not user.check_password(data["current_password"]):
            raise AuthenticationError('Current password is incorrect')
        
        # Validate new password
        if not validate_password(data["new_password"]):
            raise ValidationError(
                'New password must be 8-128 characters long and contain at least one uppercase letter, '
                'one lowercase letter, one number, and one special character.'
            )
        
        # Prevent password reuse
        if user.check_password(data["new_password"]):
            raise ValidationError('New password must be different from current password')
        
        try:
            # Update password
            user.set_password(data["new_password"])
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError('Failed to update password', details=str(e))
        
        try:
            # Revoke all existing tokens
            current_token = get_jwt()
            TokenBlocklist.revoke_token(
                jti=current_token['jti'],
                expires_at=datetime.fromtimestamp(current_token['exp']),
                token_type='access',
                user_id=user.id
            )
            
            # Revoke all other tokens for this user
            TokenBlocklist.revoke_all_user_tokens(user.id)
        except Exception as e:
            raise TokenError('Failed to revoke tokens', details=str(e))
        
        return jsonify({"message": "Password changed successfully"})
        
    except (ValidationError, AuthenticationError, ResourceNotFoundError, TokenError) as e:
        raise e
    except Exception as e:
        raise DatabaseError('Password change failed', details=str(e))
