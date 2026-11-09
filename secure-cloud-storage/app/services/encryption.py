import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from typing import Tuple

class CryptographicService:
    """
    Cryptographic Service implementing AES-256-GCM Authenticated Encryption
    with Associated Data (AEAD) as specified in NIST SP 800-38D.
    
    Guarantees:
    - Confidentiality: AES with a 256-bit symmetric key.
    - Integrity & Authenticity: 128-bit authentication tag calculated using GHASH.
    - Nonce Uniqueness: 96-bit (12-byte) cryptographically secure random nonce.
    - Plaintext Integrity Fingerprinting: SHA-256 cryptographic hash.
    """

    NONCE_LENGTH_BYTES = 12  # 96 bits recommended for GCM
    TAG_LENGTH_BYTES = 16    # 128-bit MAC tag
    KEY_LENGTH_BYTES = 32    # 256 bits

    @classmethod
    def generate_nonce(cls) -> bytes:
        """
        Generates a 96-bit cryptographically secure pseudorandom nonce.
        Never reused across encryptions with the same key.
        """
        return secrets.token_bytes(cls.NONCE_LENGTH_BYTES)

    @classmethod
    def compute_sha256(cls, data: bytes) -> str:
        """Computes SHA-256 hex digest of plaintext payload for integrity tracking."""
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypts plaintext bytes using AES-256-GCM.
        
        Args:
            plaintext: Raw file bytes.
            key: 32-byte (256-bit) encryption key.
            associated_data: Optional authenticated data (e.g. file metadata).
            
        Returns:
            Tuple of (ciphertext, nonce, auth_tag).
        """
        if len(key) != cls.KEY_LENGTH_BYTES:
            raise ValueError(f"AES-256 requires exactly 32 bytes key, got {len(key)} bytes")

        nonce = cls.generate_nonce()
        aesgcm = AESGCM(key)
        
        # cryptography's AESGCM.encrypt returns ciphertext + 16-byte tag appended
        combined = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        ciphertext = combined[:-cls.TAG_LENGTH_BYTES]
        auth_tag = combined[-cls.TAG_LENGTH_BYTES:]
        
        return ciphertext, nonce, auth_tag

    @classmethod
    def decrypt(cls, ciphertext: bytes, nonce: bytes, auth_tag: bytes, key: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypts ciphertext bytes using AES-256-GCM and verifies the authentication tag.
        
        Args:
            ciphertext: Encrypted payload bytes.
            nonce: 12-byte nonce used during encryption.
            auth_tag: 16-byte authentication tag generated during encryption.
            key: 32-byte (256-bit) decryption key.
            associated_data: Optional authenticated data.
            
        Returns:
            Decrypted original plaintext bytes.
            
        Raises:
            InvalidTag: If the ciphertext or tag has been tampered with or corrupted.
            ValueError: If inputs are invalid lengths.
        """
        if len(key) != cls.KEY_LENGTH_BYTES:
            raise ValueError(f"AES-256 requires exactly 32 bytes key, got {len(key)} bytes")
        if len(nonce) != cls.NONCE_LENGTH_BYTES:
            raise ValueError(f"Nonce must be exactly 12 bytes, got {len(nonce)} bytes")
        if len(auth_tag) != cls.TAG_LENGTH_BYTES:
            raise ValueError(f"Auth tag must be exactly 16 bytes, got {len(auth_tag)} bytes")

        aesgcm = AESGCM(key)
        combined = ciphertext + auth_tag
        
        try:
            plaintext = aesgcm.decrypt(nonce, combined, associated_data)
            return plaintext
        except InvalidTag:
            raise InvalidTag(
                "Cryptographic Authentication Tag Mismatch! "
                "The file has been modified, tampered with, or corrupted in storage."
            )
