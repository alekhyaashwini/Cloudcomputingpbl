import pytest
import io
from datetime import datetime, timezone, timedelta
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

def test_file_sharing_workflow(client, app):
    """Test full file sharing lifecycle: share, authorized download, revoke, denied download."""
    # 1. Register User 1 (Alice)
    client.post('/auth/register', data={
        'username': 'alice_share',
        'email': 'alice_share@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })

    # 2. Upload file as Alice
    file_bytes = b"Shared confidential project notes for PBL collaboration."
    client.post('/files/upload', data={
        'file': (io.BytesIO(file_bytes), 'collab_notes.txt')
    }, follow_redirects=True)

    alice = app.db.get_user_by_identifier('alice_share')
    alice_file = app.db.get_user_files(alice['id'])[0]
    file_id = alice_file['id']

    # 3. Register User 2 (Bob)
    client.get('/auth/logout')
    client.post('/auth/register', data={
        'username': 'bob_recipient',
        'email': 'bob_recipient@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    bob = app.db.get_user_by_identifier('bob_recipient')

    # Verify Bob cannot download Alice's file before sharing
    denied_res = client.get(f'/files/download/{file_id}')
    assert denied_res.status_code == 403

    # 4. Login as Alice and share with Bob (with 24h duration)
    client.get('/auth/logout')
    client.post('/auth/login', data={'identifier': 'alice_share', 'password': 'Password123!'})
    share_res = client.post(
        f'/files/share/{file_id}',
        data={'recipient': 'bob_recipient', 'duration_hours': '24'},
        follow_redirects=True
    )
    assert share_res.status_code == 200
    assert b'successfully shared' in share_res.data or b'File successfully shared' in share_res.data

    # 5. Login as Bob and successfully download Alice's shared file
    client.get('/auth/logout')
    client.post('/auth/login', data={'identifier': 'bob_recipient', 'password': 'Password123!'})

    shared_download = client.get(f'/files/download/{file_id}')
    assert shared_download.status_code == 200
    assert shared_download.data == file_bytes

    # Check shared files list for Bob
    shared_list_res = client.get('/files/shared')
    assert b'collab_notes.txt' in shared_list_res.data
    assert b'alice_share' in shared_list_res.data

    # 6. Alice revokes share
    client.get('/auth/logout')
    client.post('/auth/login', data={'identifier': 'alice_share', 'password': 'Password123!'})
    shares = app.db.get_shares_for_file(file_id, alice['id'])
    assert len(shares) == 1
    share_id = shares[0]['share_id']

    revoke_res = client.post(f'/files/revoke_share/{share_id}', data={'file_id': file_id}, follow_redirects=True)
    assert revoke_res.status_code == 200

    # 7. Bob attempts download again after revocation -> 403 Forbidden
    client.get('/auth/logout')
    client.post('/auth/login', data={'identifier': 'bob_recipient', 'password': 'Password123!'})
    revoked_download = client.get(f'/files/download/{file_id}')
    assert revoked_download.status_code == 403

def test_expired_share_denial(client, app):
    """Test that time-expired share is rejected with 403."""
    # Register Owner
    client.post('/auth/register', data={
        'username': 'owner_expiry',
        'email': 'expiry@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    client.post('/files/upload', data={
        'file': (io.BytesIO(b'Time-sensitive data'), 'expiry_test.txt')
    }, follow_redirects=True)
    owner = app.db.get_user_by_identifier('owner_expiry')
    file_id = app.db.get_user_files(owner['id'])[0]['id']

    # Register Recipient
    client.get('/auth/logout')
    client.post('/auth/register', data={
        'username': 'recipient_expiry',
        'email': 'recip_exp@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    recip = app.db.get_user_by_identifier('recipient_expiry')

    # Create share that is already expired (e.g. yesterday) directly in DB
    past_date = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
    with app.db.get_connection() as conn:
        conn.execute('''
            INSERT INTO file_shares (file_id, owner_id, shared_with_user_id, expires_at, is_revoked)
            VALUES (?, ?, ?, ?, 0)
        ''', (file_id, owner['id'], recip['id'], past_date))
        conn.commit()

    # Recipient attempts download -> must be rejected as expired
    client.get('/auth/logout')
    client.post('/auth/login', data={'identifier': 'recipient_expiry', 'password': 'Password123!'})
    res = client.get(f'/files/download/{file_id}')
    assert res.status_code == 403

def test_file_details_api(client, app):
    """Test cryptographic details API endpoint."""
    client.post('/auth/register', data={
        'username': 'inspector',
        'email': 'inspect@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    client.post('/files/upload', data={
        'file': (io.BytesIO(b'Metadata inspection test'), 'metadata.txt')
    }, follow_redirects=True)

    user = app.db.get_user_by_identifier('inspector')
    file_id = app.db.get_user_files(user['id'])[0]['id']

    res = client.get(f'/files/details/{file_id}')
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['cipher'] == 'AES-256-GCM (AEAD)'
    assert 'sha256_hash' in json_data
    assert 'file_nonce_hex' in json_data
    assert 'wrapped_dek_preview' in json_data

def test_audit_logs_and_csv_export(client, app):
    """Test that audit events are logged and exportable to CSV."""
    client.post('/auth/register', data={
        'username': 'audit_officer',
        'email': 'audit@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    client.post('/auth/login', data={'identifier': 'audit_officer', 'password': 'Password123!'})
    
    # Check security center view
    res = client.get('/security/')
    assert res.status_code == 200
    assert b'Security Audit Log' in res.data

    # Check CSV export
    csv_res = client.get('/security/export_audit_logs')
    assert csv_res.status_code == 200
    assert csv_res.mimetype == 'text/csv'
    assert b'Event Type' in csv_res.data
    assert b'USER_REGISTERED' in csv_res.data
