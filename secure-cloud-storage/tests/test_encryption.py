import pytest
import os
from cryptography.exceptions import InvalidTag
from app.services.encryption import CryptographicService
from app.services.key_management import KeyManagementService

def test_aes_gcm_encryption_roundtrip():
    """Verify that plaintext encrypted with AES-256-GCM decrypts cleanly to identical bytes."""
    key = os.urandom(32)
    plaintext = b"This is a confidential college project file to test AES-256-GCM."
    
    ciphertext, nonce, auth_tag = CryptographicService.encrypt(plaintext, key)
    
    assert len(nonce) == 12, "Nonce must be 96 bits (12 bytes)"
    assert len(auth_tag) == 16, "Auth tag must be 128 bits (16 bytes)"
    assert ciphertext != plaintext, "Ciphertext must never match plaintext"
    
    decrypted = CryptographicService.decrypt(ciphertext, nonce, auth_tag, key)
    assert decrypted == plaintext, "Decrypted bytes must match original plaintext"

def test_empty_file_encryption():
    """Verify zero-byte empty file handles encryption and decryption without errors."""
    key = os.urandom(32)
    plaintext = b""
    
    ciphertext, nonce, auth_tag = CryptographicService.encrypt(plaintext, key)
    decrypted = CryptographicService.decrypt(ciphertext, nonce, auth_tag, key)
    assert decrypted == b""

def test_binary_file_encryption():
    """Verify arbitrary binary payloads (e.g. image or compiled binary bytes) are preserved."""
    key = os.urandom(32)
    binary_data = bytes(range(256)) * 10
    
    ciphertext, nonce, auth_tag = CryptographicService.encrypt(binary_data, key)
    decrypted = CryptographicService.decrypt(ciphertext, nonce, auth_tag, key)
    assert decrypted == binary_data

def test_unique_nonce_per_operation():
    """Verify that consecutive encryptions of identical data generate distinct nonces."""
    key = os.urandom(32)
    data = b"identical repeated plaintext"
    
    _, nonce1, _ = CryptographicService.encrypt(data, key)
    _, nonce2, _ = CryptographicService.encrypt(data, key)
    
    assert nonce1 != nonce2, "CSPRNG Nonces must be unique per encryption to prevent keystream reuse"

def test_tampered_ciphertext_detection():
    """Verify that single-bit flip in ciphertext raises InvalidTag exception."""
    key = os.urandom(32)
    plaintext = b"Highly sensitive university research document."
    
    ciphertext, nonce, auth_tag = CryptographicService.encrypt(plaintext, key)
    
    # Tamper with first byte
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0x01
    
    with pytest.raises(InvalidTag):
        CryptographicService.decrypt(bytes(tampered_ciphertext), nonce, auth_tag, key)

def test_tampered_auth_tag_detection():
    """Verify that modified authentication tag causes decryption to be rejected."""
    key = os.urandom(32)
    plaintext = b"Testing authentication tag validation."
    
    ciphertext, nonce, auth_tag = CryptographicService.encrypt(plaintext, key)
    
    # Tamper with authentication tag
    tampered_tag = bytearray(auth_tag)
    tampered_tag[-1] ^= 0xFF
    
    with pytest.raises(InvalidTag):
        CryptographicService.decrypt(ciphertext, nonce, bytes(tampered_tag), key)

def test_wrong_key_rejection():
    """Verify that attempting decryption with an incorrect key raises InvalidTag."""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    plaintext = b"Target file content."
    
    ciphertext, nonce, auth_tag = CryptographicService.encrypt(plaintext, key1)
    
    with pytest.raises(InvalidTag):
        CryptographicService.decrypt(ciphertext, nonce, auth_tag, key2)

def test_envelope_encryption_dek_wrapping():
    """Verify that DEK is securely wrapped and unwrapped using KEK (Envelope Encryption)."""
    km = KeyManagementService("master_secret_key_at_least_16_chars")
    salt = km.generate_salt()
    kek = km.derive_kek(user_id=101, salt=salt)
    dek = km.generate_dek()

    wrapped_dek, wrap_nonce, wrap_tag = km.wrap_dek(dek, kek)
    assert len(wrapped_dek) == 32
    assert wrapped_dek != dek

    unwrapped_dek = km.unwrap_dek(wrapped_dek, wrap_nonce, wrap_tag, kek)
    assert unwrapped_dek == dek

    # Tampering with wrapped DEK should raise InvalidTag
    tampered_wrap = bytearray(wrapped_dek)
    tampered_wrap[0] ^= 0x55
    with pytest.raises(InvalidTag):
        km.unwrap_dek(bytes(tampered_wrap), wrap_nonce, wrap_tag, kek)

def test_sha256_plaintext_fingerprint():
    """Verify SHA-256 fingerprint correctly detects data alteration."""
    data = b"PBL Final Year Demonstration"
    digest = CryptographicService.compute_sha256(data)
    assert len(digest) == 64
    assert digest == CryptographicService.compute_sha256(data)
    assert digest != CryptographicService.compute_sha256(b"PBL Final Year DemonstratioN")
