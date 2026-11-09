from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from functools import wraps

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access your secure vault.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    """Extract client IP, taking into account X-Forwarded-For if behind a reverse proxy."""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validations
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long for security.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        # Check existing account
        existing = current_app.db.get_user_by_identifier(username) or current_app.db.get_user_by_identifier(email)
        if existing:
            current_app.db.log_event(
                user_id=None,
                username=username,
                event_type='REGISTRATION_ATTEMPT',
                details=f'Rejected duplicate registration attempt for username "{username}" or email "{email}"',
                ip_address=get_client_ip(),
                status='WARNING'
            )
            flash('Username or email is already registered. Please log in.', 'danger')
            return render_template('register.html')

        user_id = current_app.db.create_user(username, email, password)
        if user_id:
            current_app.db.log_event(
                user_id=user_id,
                username=username,
                event_type='USER_REGISTERED',
                details='New account created with salted password hash',
                ip_address=get_client_ip(),
                status='SUCCESS'
            )
            session.clear()
            session['user_id'] = user_id
            session['username'] = username
            session['email'] = email.strip().lower()
            flash('Registration successful! Welcome to your secure vault.', 'success')
            return redirect(url_for('files.dashboard'))
        else:
            flash('Failed to create account. Please try again.', 'danger')

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        if not identifier or not password:
            flash('Please provide your username/email and password.', 'danger')
            return render_template('login.html')

        user = current_app.db.get_user_by_identifier(identifier)
        if user and current_app.db.verify_password(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            
            current_app.db.log_event(
                user_id=user['id'],
                username=user['username'],
                event_type='AUTH_LOGIN_SUCCESS',
                details='User authenticated successfully and session established',
                ip_address=get_client_ip(),
                status='SUCCESS'
            )
            
            flash(f'Welcome back, {user["username"]}! Authenticated to Secure Vault.', 'success')
            return redirect(url_for('files.dashboard'))
        else:
            current_app.db.log_event(
                user_id=user['id'] if user else None,
                username=identifier,
                event_type='AUTH_LOGIN_FAILED',
                details=f'Failed login attempt with identifier "{identifier}"',
                ip_address=get_client_ip(),
                status='SECURITY_ALERT'
            )
            flash('Invalid username/email or password.', 'danger')

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if user_id:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='AUTH_LOGOUT',
            details='User logged out; session terminated',
            ip_address=get_client_ip(),
            status='INFO'
        )
        
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))
