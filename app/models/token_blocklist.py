from app import db
from datetime import datetime

class TokenBlocklist(db.Model):
    """Model for storing revoked tokens"""
    __tablename__ = 'token_blocklist'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    token_type = db.Column(db.String(10), nullable=False)  # 'access' or 'refresh'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, jti, expires_at, token_type, user_id):
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
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)

    @classmethod
    def revoke_token(cls, jti, expires_at, token_type, user_id):
        """Add a token to the blocklist"""
        blocklist_entry = cls(
            jti=jti,
            expires_at=expires_at,
            token_type=token_type,
            user_id=user_id
        )
        db.session.add(blocklist_entry)
        db.session.commit()
        return blocklist_entry

    @classmethod
    def cleanup_expired_tokens(cls):
        """Remove expired tokens from the blocklist"""
        cls.query.filter(cls.expires_at < datetime.utcnow()).delete()
        db.session.commit() 