from app import db
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_

class TokenBlocklist(db.Model):
    """Model for storing revoked tokens"""
    __tablename__ = 'token_blocklist'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    token_type = db.Column(db.String(10), nullable=False)  # 'access' or 'refresh'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    __table_args__ = (
        db.Index('idx_token_blocklist_user_expires', 'user_id', 'expires_at'),
    )

    def __init__(self, jti, expires_at, token_type, user_id):
        if not jti or not isinstance(jti, str):
            raise ValueError("JTI must be a non-empty string")
        if not expires_at or not isinstance(expires_at, datetime):
            raise ValueError("Expires at must be a valid datetime")
        if token_type not in ['access', 'refresh']:
            raise ValueError("Token type must be either 'access' or 'refresh'")
        if not user_id or not isinstance(user_id, int):
            raise ValueError("User ID must be a valid integer")
            
        self.jti = jti
        self.expires_at = expires_at
        self.token_type = token_type
        self.user_id = user_id

    def to_dict(self):
        return {
            'id': self.id,
            'jti': self.jti,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'revoked_at': self.revoked_at.isoformat(),
            'token_type': self.token_type,
            'user_id': self.user_id
        }

    @classmethod
    def is_jti_revoked(cls, jti):
        """Check if a JTI is in the blocklist"""
        try:
            if not jti:
                return False
            query = cls.query.filter_by(jti=jti).first()
            return bool(query)
        except SQLAlchemyError:
            return False

    @classmethod
    def revoke_token(cls, jti, expires_at, token_type, user_id):
        """Add a token to the blocklist"""
        try:
            # Check if token is already revoked
            if cls.is_jti_revoked(jti):
                return None
                
            # Validate inputs
            if not jti or not isinstance(jti, str):
                raise ValueError("JTI must be a non-empty string")
            if not expires_at or not isinstance(expires_at, datetime):
                raise ValueError("Expires at must be a valid datetime")
            if token_type not in ['access', 'refresh']:
                raise ValueError("Token type must be either 'access' or 'refresh'")
            if not user_id or not isinstance(user_id, int):
                raise ValueError("User ID must be a valid integer")
            
            blocklist_entry = cls(
                jti=jti,
                expires_at=expires_at,
                token_type=token_type,
                user_id=user_id
            )
            db.session.add(blocklist_entry)
            db.session.commit()
            return blocklist_entry
        except IntegrityError:
            db.session.rollback()
            return None
        except SQLAlchemyError as e:
            db.session.rollback()
            raise e

    @classmethod
    def cleanup_expired_tokens(cls):
        """Remove expired tokens from the blocklist"""
        try:
            cls.query.filter(cls.expires_at < datetime.utcnow()).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            raise e

    @classmethod
    def revoke_all_user_tokens(cls, user_id):
        """Revoke all tokens for a specific user"""
        try:
            if not user_id or not isinstance(user_id, int):
                raise ValueError("User ID must be a valid integer")
                
            current_time = datetime.utcnow()
            tokens = cls.query.filter_by(user_id=user_id).all()
            
            for token in tokens:
                token.revoked_at = current_time
                
            db.session.commit()
            return len(tokens)
        except SQLAlchemyError as e:
            db.session.rollback()
            raise e

    @classmethod
    def get_user_active_tokens(cls, user_id):
        """Get all active tokens for a user"""
        try:
            if not user_id or not isinstance(user_id, int):
                raise ValueError("User ID must be a valid integer")
                
            current_time = datetime.utcnow()
            return cls.query.filter(
                and_(
                    cls.user_id == user_id,
                    cls.expires_at > current_time
                )
            ).all()
        except SQLAlchemyError as e:
            raise e

    @classmethod
    def is_token_valid(cls, jti, user_id):
        """Check if a token is valid for a user"""
        try:
            if not jti or not user_id:
                return False
                
            current_time = datetime.utcnow()
            token = cls.query.filter(
                and_(
                    cls.jti == jti,
                    cls.user_id == user_id,
                    cls.expires_at > current_time
                )
            ).first()
            
            return token is not None
        except SQLAlchemyError:
            return False 