import re
from flask import jsonify

def validate_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if re.match(pattern, email) is None:
        return False
    return True

def validate_password(password):
    """
    Validate password strength:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    
    # Check for at least one number
    if not re.search(r'\d', password):
        return False
    
    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True

def validate_amount(amount):
    """Amount must be positive"""
    try:
        amount = float(amount)
        if amount <= 0:
            return False
        return True
    except (ValueError, TypeError):
        return False

def error_response(message, status_code=400):
    """Return a standardized error response"""
    return jsonify({"message": message}), status_code 