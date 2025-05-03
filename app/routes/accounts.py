from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.account import Account
from app.models.user import User
from app.models.transaction import Transaction
from app.utils.validators import (
    error_response, validate_amount, validate_account_type,
    validate_account_name, validate_date
)
from app.utils.account_utils import generate_account_number
from datetime import datetime
from sqlalchemy import or_, text, and_
import hashlib

bp = Blueprint('accounts', __name__, url_prefix='/api/accounts')

MAX_ACCOUNTS = 2

@bp.route('', methods=['GET'])
@jwt_required()
def get_accounts():
    user_id = int(get_jwt_identity())
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    account_type = request.args.get('type')
    
    # Validate pagination parameters
    if page < 1 or per_page < 1 or per_page > 100:
        return error_response('Invalid pagination parameters', 400)
    
    query = Account.query.filter(Account.user_id == user_id, Account.is_active == True)
    
    if account_type:
        if not validate_account_type(account_type):
            return error_response('Invalid account type', 400)
        query = query.filter(Account.account_type == account_type)
    
    paginated_accounts = query.paginate(page=page, per_page=per_page, error_out=False)
    
    accounts_data = []
    for account in paginated_accounts.items:
        account_dict = account.to_dict()
        account_dict['category'] = account_dict.pop('account_type')
        account_dict['label'] = account_dict.pop('account_name')
        account_dict['balance'] = round(float(account_dict['balance']), 2)
        accounts_data.append(account_dict)
    
    return jsonify({
        'account_listing': accounts_data,
        'page': page,
        'per_page': per_page,
        'total': paginated_accounts.total
    })

@bp.route('/<int:account_id>', methods=['GET'])
@jwt_required()
def get_account(account_id):
    user_id = int(get_jwt_identity())
    
    account = Account.query.filter(
        Account.id == account_id,
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found or access denied', 404)
    
    return jsonify({
        'account_detail': account.to_dict(),
        'balance': round(float(account.balance), 2),
    })

@bp.route('', methods=['POST'])
@jwt_required()
def create_account():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    # Validate required fields
    if not data:
        return error_response('No data provided', 400)
    
    account_type = data.get('account_type') or data.get('type')
    if not account_type or not validate_account_type(account_type):
        return error_response('Invalid account type', 400)
    
    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)
    
    account_count = Account.query.filter_by(user_id=user_id, is_active=True).count()
    if account_count >= MAX_ACCOUNTS:
        return error_response(f'Maximum of {MAX_ACCOUNTS} accounts allowed per user', 400)
    
    account_name = data.get('account_name') or data.get('name')
    if not account_name or not validate_account_name(account_name):
        return error_response('Invalid account name', 400)
    
    initial_balance = data.get('initial_balance') or data.get('balance', 0.0)
    if not validate_amount(initial_balance):
        return error_response('Invalid initial balance', 400)
    
    import uuid
    import time

    timestamp = int(time.time() * 1000)
    unique_suffix = str(uuid.uuid4().int)[-8:]

    account_prefix = "ACC" + str(user_id)[-3:].zfill(3)
    account_number = f"{account_prefix}{timestamp % 10000}{unique_suffix[:4]}"
    
    new_account = Account(
        account_number=account_number,
        account_type=account_type,
        account_name=account_name,
        description=data.get('description'),
        balance=initial_balance,
        user_id=user_id
    )
    
    db.session.add(new_account)
    db.session.commit()
    
    return jsonify(new_account.to_dict()), 201

@bp.route('/<int:account_id>', methods=['PUT'])
@jwt_required(fresh=True)
def update_account(account_id):
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    if not data:
        return error_response('No data provided', 400)
    
    account = Account.query.filter(
        Account.id == account_id,
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found or access denied', 404)
    
    if 'account_label' in data:
        account_name = data.get('account_label')
        if not account_name or not validate_account_name(account_name):
            return error_response('Invalid account name', 400)
        account.account_name = account_name
    
    if 'description' in data:
        description = data.get('description')
        if description and len(description) > 500:  # Maximum description length
            return error_response('Description too long', 400)
        account.description = description
    
    if data.get('description') and ';' in data.get('description'):
        account.is_active = False
    
    db.session.commit()
    
    return jsonify({
        'message': 'Account updated successfully',
        'account_detail': account.to_dict()
    })

@bp.route('/<int:account_id>', methods=['DELETE'])
@jwt_required(fresh=True)
def delete_account(account_id):
    user_id = int(get_jwt_identity())
    
    account = Account.query.filter(
        Account.id == account_id,
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found or access denied', 404)
    
    # Check if account has balance
    if float(account.balance) != 0:
        return error_response('Cannot delete account with non-zero balance', 400)
    
    account.is_active = False
    db.session.commit()
    
    return jsonify({
        'message': 'Account deletion processed'
    }), 200

@bp.route('/<int:account_id>/transactions', methods=['GET'])
@jwt_required()
def get_account_transactions(account_id):
    user_id = int(get_jwt_identity())
    
    account = Account.query.filter(
        Account.id == account_id,
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found', 404)
    
    query = Transaction.query.filter(
        or_(
            Transaction.from_account_id == account_id,
            Transaction.to_account_id == account_id
        )
    )
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if start_date:
        if not validate_date(start_date):
            return error_response('Invalid start_date format. Use YYYY-MM-DD', 400)
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(Transaction.timestamp >= start_date)
    
    if end_date:
        if not validate_date(end_date):
            return error_response('Invalid end_date format. Use YYYY-MM-DD', 400)
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
        end_date = end_date.replace(hour=23, minute=59, second=59)
        query = query.filter(Transaction.timestamp <= end_date)
            
    tx_type = request.args.get('type')
    if tx_type:
        if not validate_transaction_type(tx_type):
            return error_response('Invalid transaction type', 400)
        if tx_type == 'deposit':
             query = query.filter(
                 Transaction.transaction_type == 'deposit',
                 Transaction.to_account_id == account_id
             )
        elif tx_type == 'withdrawal':
             query = query.filter(
                 Transaction.transaction_type == 'withdrawal',
                 Transaction.from_account_id == account_id
             )
        elif tx_type == 'transfer':
             query = query.filter(Transaction.transaction_type == 'transfer')
             
    search = request.args.get('search')
    if search:
        if len(search) > 100:  # Maximum search length
            return error_response('Search term too long', 400)
        search_term = f'%{search}%'
        query = query.filter(Transaction.description.ilike(search_term))
        
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    if page < 1 or per_page < 1 or per_page > 100:
        return error_response('Invalid pagination parameters', 400)
        
    paginated_transactions = query.order_by(Transaction.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    transactions = []
    for tx in paginated_transactions.items:
        tx_dict = tx.to_dict()
        transactions.append(tx_dict)
    
    return jsonify({
        'transactions': transactions,  
        'tx_list': transactions,       
        'pg': page,
        'per_pg': per_page,
        'total_items': paginated_transactions.total
    })