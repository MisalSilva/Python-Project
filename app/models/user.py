from app import db, bcrypt
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    """User model for storing user related details"""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    accounts = db.relationship('Account', backref='user', lazy=True, cascade='all, delete-orphan')
    tokens = db.relationship('TokenBlocklist', backref='user', lazy=True, cascade='all, delete-orphan')

    def __init__(self, email, username, first_name, last_name, role='user'):
        self.email = email.lower().strip()
        self.username = username.lower().strip()
        self.first_name = first_name.strip()
        self.last_name = last_name.strip()
        self.role = role.lower()

    def set_password(self, password):
        """Set password hash"""
        if not password:
            raise ValueError("Password cannot be empty")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password hash"""
        if not password:
            return False
        return check_password_hash(self.password_hash, password)

    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            raise

    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    @classmethod
    def get_by_id(cls, user_id):
        """Get user by ID"""
        try:
            return cls.query.get(user_id)
        except SQLAlchemyError:
            return None

    @classmethod
    def get_by_email(cls, email):
        """Get user by email"""
        try:
            return cls.query.filter_by(email=email.lower().strip()).first()
        except SQLAlchemyError:
            return None

    @classmethod
    def get_by_username(cls, username):
        """Get user by username"""
        try:
            return cls.query.filter_by(username=username.lower().strip()).first()
        except SQLAlchemyError:
            return None

    def update(self, **kwargs):
        """Update user attributes"""
        allowed_fields = {'email', 'username', 'first_name', 'last_name', 'role', 'is_active'}
        
        for key, value in kwargs.items():
            if key in allowed_fields:
                if key in ['email', 'username']:
                    value = value.lower().strip()
                elif key in ['first_name', 'last_name']:
                    value = value.strip()
                setattr(self, key, value)
        
        try:
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False

    def delete(self):
        """Delete user"""
        try:
            db.session.delete(self)
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False

    def __repr__(self):
        return f'<User {self.username}>' 