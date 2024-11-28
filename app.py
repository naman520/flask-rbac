from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
import jwt
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# MySQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/rbac'
app.config['SECRET_KEY'] = 'xampp_rbac_secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# RBAC Models
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary='role_permissions')

class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class RolePermissions(db.Model):
    __tablename__ = 'role_permissions'
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), primary_key=True)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

# RBAC Decorator
def role_required(permissions=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Token verification
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'message': 'Token missing'}), 401
            
            try:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = User.query.get(payload['user_id'])
                
                # Permission check
                if permissions:
                    user_permissions = [p.name for p in current_user.role.permissions]
                    if not all(perm in user_permissions for perm in permissions):
                        return jsonify({'message': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token'}), 401
        
        return decorated_function
    return decorator

# Authentication Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check existing user
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User exists'}), 400
    
    # Hash password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Default role (first role)
    role = Role.query.first()
    
    # Create user
    new_user = User(
        username=data['username'], 
        password=hashed_password, 
        role=role
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Find user
    user = User.query.filter_by(username=data['username']).first()
    
    # Validate credentials
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Generate JWT token
        token_payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.name,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({
            'token': token,
            'user_id': user.id,
            'role': user.role.name
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

# Protected Routes
@app.route('/admin', methods=['GET'])
@role_required(permissions=['admin_access'])
def admin_dashboard():
    return jsonify({'message': 'Admin dashboard'})

@app.route('/reports', methods=['GET'])
@role_required(permissions=['view_reports'])
def view_reports():
    return jsonify({'message': 'Reports accessed'})

# Initial Setup Function
def setup_rbac():
    # Create Permissions
    permissions = [
        Permission(name='admin_access'),
        Permission(name='view_reports'),
        Permission(name='edit_user')
    ]
    
    # Add permissions to the database
    db.session.add_all(permissions)
    db.session.commit()  # Commit to ensure they are saved and queryable

    # Fetch permissions from the database
    admin_access = Permission.query.filter_by(name='admin_access').first()
    view_reports = Permission.query.filter_by(name='view_reports').first()
    edit_user = Permission.query.filter_by(name='edit_user').first()
    
    # Create Roles
    admin_role = Role(name='admin', permissions=[admin_access, view_reports, edit_user])
    user_role = Role(name='user', permissions=[view_reports])
    
    # Save roles to the database
    db.session.add_all([admin_role, user_role])
    db.session.commit()


# Initialize Database
with app.app_context():
    db.create_all()
    if Role.query.count() == 0:
        setup_rbac()

if __name__ == '__main__':
    app.run(debug=True)