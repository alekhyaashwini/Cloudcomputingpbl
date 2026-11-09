import pytest
from app import create_app
from config import TestingConfig

@pytest.fixture
def app():
    app = create_app(TestingConfig)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_user_registration(client, app):
    """Test user registration stores salted hash, not plaintext."""
    res = client.post('/auth/register', data={
        'username': 'alice',
        'email': 'alice@college.edu',
        'password': 'SecurePassword123!',
        'confirm_password': 'SecurePassword123!'
    }, follow_redirects=True)
    
    assert res.status_code == 200
    user = app.db.get_user_by_identifier('alice')
    assert user is not None
    assert user['username'] == 'alice'
    assert user['password_hash'] != 'SecurePassword123!'
    assert 'pbkdf2' in user['password_hash'] or 'scrypt' in user['password_hash']

def test_duplicate_registration_rejected(client):
    """Test that duplicate username or email is refused."""
    client.post('/auth/register', data={
        'username': 'bob',
        'email': 'bob@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    
    # Attempt duplicate
    res = client.post('/auth/register', data={
        'username': 'bob',
        'email': 'different_email@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    }, follow_redirects=True)
    
    assert b'already registered' in res.data or b'danger' in res.data

def test_login_success_and_session(client):
    """Test login with valid credentials creates authenticated session."""
    client.post('/auth/register', data={
        'username': 'charlie',
        'email': 'charlie@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    
    res = client.post('/auth/login', data={
        'identifier': 'charlie',
        'password': 'Password123!'
    }, follow_redirects=True)
    
    assert res.status_code == 200
    assert b'Dashboard' in res.data or b'Authenticated' in res.data

def test_invalid_credentials_rejected(client):
    """Test wrong password fails authentication."""
    res = client.post('/auth/login', data={
        'identifier': 'nonexistent_user',
        'password': 'WrongPassword!'
    }, follow_redirects=True)
    
    assert b'Invalid username/email or password' in res.data

def test_unauthenticated_dashboard_redirect(client):
    """Test accessing /files/dashboard without logging in redirects to login."""
    res = client.get('/files/dashboard')
    assert res.status_code == 302
    assert '/auth/login' in res.headers['Location']
