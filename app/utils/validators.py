import re
from flask import jsonify
from datetime import datetime

def validate_email(email):
    """
    Validate email format and ensure it's a valid Google account
    - Must be a valid email format
    - Must be from a Google domain (gmail.com, googlemail.com)
    - Must not contain special characters except ._-@
    - Must follow Gmail's username rules
    """
    if not email or not isinstance(email, str):
        return False
        
    # Check if it's a Google email
    email = email.lower()
    if not email.endswith('@gmail.com') and not email.endswith('@googlemail.com'):
        return False
        
    # Basic email pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
        
    # Additional checks
    if len(email) > 254:  # RFC 5321
        return False
        
    # Check for consecutive dots
    if '..' in email:
        return False
        
    # Gmail specific rules
    username = email.split('@')[0]
    
    # Gmail usernames must be 6-30 characters
    if len(username) < 6 or len(username) > 30:
        return False
        
    # Gmail usernames can only contain letters, numbers, dots, and underscores
    if not re.match(r'^[a-z0-9._]+$', username):
        return False
        
    # Gmail doesn't allow consecutive dots
    if '..' in username:
        return False
        
    # Gmail doesn't allow dots at the start or end of username
    if username.startswith('.') or username.endswith('.'):
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
    - Maximum length of 128 characters
    - No whitespace
    """
    if not password or not isinstance(password, str):
        return False
        
    if len(password) < 8 or len(password) > 128:
        return False
        
    if ' ' in password:
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
    """
    Validate monetary amount:
    - Must be a positive number
    - Maximum 2 decimal places
    - Maximum value of 999999999.99
    """
    try:
        amount = float(amount)
        if amount <= 0:
            return False
        if amount > 999999999.99:
            return False
        # Check decimal places
        if len(str(amount).split('.')[-1]) > 2:
            return False
        return True
    except (ValueError, TypeError):
        return False

def validate_date(date_str):
    """
    Validate date format (YYYY-MM-DD)
    - Must be valid date
    - Must not be in the future
    """
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d')
        if date > datetime.now():
            return False
        return True
    except ValueError:
        return False

def validate_username(username):
    """
    Validate username:
    - 3-50 characters long
    - Alphanumeric with underscores and hyphens
    - Must start with a letter
    """
    if not username or not isinstance(username, str):
        return False
        
    if len(username) < 3 or len(username) > 50:
        return False
        
    pattern = r'^[a-zA-Z][a-zA-Z0-9_-]*$'
    return bool(re.match(pattern, username))

def validate_name(name):
    """
    Validate name (first/last name):
    - 2-50 characters long
    - Letters, spaces, hyphens, and apostrophes only
    - Must start with a letter
    """
    if not name or not isinstance(name, str):
        return False
        
    if len(name) < 2 or len(name) > 50:
        return False
        
    pattern = r'^[a-zA-Z][a-zA-Z\s\'-]*$'
    return bool(re.match(pattern, name))

def validate_account_type(account_type):
    """
    Validate account type
    """
    valid_types = ['checking', 'savings', 'investment']
    return account_type in valid_types

def validate_account_name(name):
    """
    Validate account name:
    - 3-90 characters long
    - Alphanumeric with spaces and basic punctuation
    """
    if not name or not isinstance(name, str):
        return False
        
    if len(name) < 3 or len(name) > 90:
        return False
        
    pattern = r'^[a-zA-Z0-9\s.,\'-]+$'
    return bool(re.match(pattern, name))

def validate_transaction_type(tx_type):
    """
    Validate transaction type
    """
    valid_types = ['deposit', 'withdrawal', 'transfer']
    return tx_type in valid_types

def error_response(message, status_code=400):
    """Return a standardized error response"""
    return jsonify({
        "error": True,
        "message": message,
        "status_code": status_code
    }), status_code 