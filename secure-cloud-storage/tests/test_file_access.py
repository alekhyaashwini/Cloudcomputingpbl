import pytest
import io
from app import create_app
from config import TestingConfig

@pytest.fixture
def app(tmp_path):
    class CustomTestingConfig(TestingConfig):
        LOCAL_STORAGE_DIR = str(tmp_path / 'vault')

    app = create_app(CustomTestingConfig)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_cross_user_file_access_denied(client, app):
    """Verify that User 2 cannot download or delete User 1's encrypted file without explicit share."""
    # Register User 1
    client.post('/auth/register', data={
        'username': 'owner_user',
        'email': 'owner@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    
    # Upload file as User 1
    file_content = b"Confidential document belonging to owner_user."
    upload_res = client.post('/files/upload', data={
        'file': (io.BytesIO(file_content), 'owner_secret.txt')
    }, follow_redirects=True)
    assert upload_res.status_code == 200

    # Obtain file ID from database
    user1 = app.db.get_user_by_identifier('owner_user')
    files = app.db.get_user_files(user1['id'])
    assert len(files) == 1
    target_file_id = files[0]['id']

    # Logout User 1
    client.get('/auth/logout')

    # Register and login User 2
    client.post('/auth/register', data={
        'username': 'attacker_user',
        'email': 'attacker@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })

    # User 2 attempts to download User 1's file -> 403 Forbidden
    cross_download = client.get(f'/files/download/{target_file_id}')
    assert cross_download.status_code == 403, "Must return 403 Forbidden on cross-user file download"

    # User 2 attempts to delete User 1's file -> 403 Forbidden
    cross_delete = client.post(f'/files/delete/{target_file_id}')
    assert cross_delete.status_code == 403, "Must return 403 Forbidden on cross-user file deletion"
