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

def test_tampered_stored_ciphertext_rejection(client, app):
    """Verify that tampering with ciphertext at rest causes download failure with security alert."""
    # Register & login
    client.post('/auth/register', data={
        'username': 'student_tester',
        'email': 'tester@college.edu',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    })

    # Upload file
    plaintext = b"PBL Final Project: Cryptographic integrity test payload."
    client.post('/files/upload', data={
        'file': (io.BytesIO(plaintext), 'pbl_report.pdf')
    }, follow_redirects=True)

    user = app.db.get_user_by_identifier('student_tester')
    file_record = app.db.get_user_files(user['id'])[0]

    # Tamper with the raw encrypted file in the storage backend
    raw_encrypted_bytes = app.storage_adapter.retrieve(file_record['storage_key'])
    corrupted_bytes = bytearray(raw_encrypted_bytes)
    corrupted_bytes[0] ^= 0xAA  # Flip bits in ciphertext
    app.storage_adapter.save(file_record['storage_key'], bytes(corrupted_bytes))

    # Attempt download -> must fail and alert
    res = client.get(f'/files/download/{file_record["id"]}', follow_redirects=True)
    assert b'Cryptographic Authentication Tag Mismatch' in res.data or b'danger' in res.data

    # Verify security audit log captured the tampering incident
    alerts = [l for l in app.db.get_audit_logs() if l['status'] == 'SECURITY_ALERT']
    assert len(alerts) > 0
    assert any('INTEGRITY_VIOLATION_TAMPERING' in a['event_type'] for a in alerts)
