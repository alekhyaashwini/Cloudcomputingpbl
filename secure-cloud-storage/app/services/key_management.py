import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from typing import Tuple

class KeyManagementService:
    """
    Key Management Service implementing Envelope Encryption (NIST SP 800-57).
    
    Architecture:
    1. Master Key (KEK - Key Encryption Key): Central server secret from MASTER_ENCRYPTION_KEY env var.
    2. Data Encryption Key (DEK): Fresh 256-bit CSPRNG key generated per file.
    3. Key Wrapping: DEK is encrypted/wrapped using the tenant-isolated KEK via AES-256-GCM.
    4. Key Derivation: KEK is derived via PBKDF2-HMAC-SHA256 (100,000 iterations)
       mixing Master Key, per-file 16-byte random salt, and tenant ID.
    5. Plaintext DEK is never stored in database or cloud storage.
    """

    ITERATIONS = 100000
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12 # 96 bits
    TAG_SIZE = 16  # 128 bits
    KEY_VERSION = "v1-envelope-pbkdf2"

    def __init__(self, master_key: str):
        if not master_key or len(master_key) < 16:
            raise ValueError("Master encryption key must be at least 16 characters long.")
        self.master_key = master_key.encode('utf-8')

    @classmethod
    def generate_salt(cls) -> bytes:
        """Generates a fresh 16-byte random salt for key derivation."""
        return secrets.token_bytes(16)

    @classmethod
    def generate_dek(cls) -> bytes:
        """Generates a fresh 256-bit (32 bytes) Data Encryption Key (DEK)."""
        return secrets.token_bytes(cls.KEY_SIZE)

    def derive_kek(self, user_id: int, salt: bytes) -> bytes:
        """
        Derives an isolated 256-bit Key Encryption Key (KEK) for a specific user and file.
        
        Args:
            user_id: Unique integer ID of the file owner.
            salt: 16-byte random salt stored alongside file metadata.
            
        Returns:
            32-byte symmetric key (KEK).
        """
        if len(salt) != 16:
            raise ValueError(f"Salt must be 16 bytes, got {len(salt)}")

        context = f"user_context_{user_id}".encode('utf-8')
        combined_secret = self.master_key + b"::" + context

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS
        )
        return kdf.derive(combined_secret)

    def wrap_dek(self, dek: bytes, kek: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Wraps (encrypts) the Data Encryption Key (DEK) using the Key Encryption Key (KEK)
        via AES-256-GCM.
        
        Returns:
            Tuple of (wrapped_dek, wrap_nonce, wrap_tag).
        """
        if len(dek) != self.KEY_SIZE:
            raise ValueError(f"DEK must be 32 bytes, got {len(dek)}")
        if len(kek) != self.KEY_SIZE:
            raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")

        wrap_nonce = secrets.token_bytes(self.NONCE_SIZE)
        aesgcm = AESGCM(kek)
        combined = aesgcm.encrypt(wrap_nonce, dek, b"envelope_dek_wrapping")
        
        wrapped_dek = combined[:-self.TAG_SIZE]
        wrap_tag = combined[-self.TAG_SIZE:]
        return wrapped_dek, wrap_nonce, wrap_tag

    def unwrap_dek(self, wrapped_dek: bytes, wrap_nonce: bytes, wrap_tag: bytes, kek: bytes) -> bytes:
        """
        Unwraps (decrypts and authenticates) the Data Encryption Key (DEK).
        
        Returns:
            Original 32-byte DEK.
            
        Raises:
            InvalidTag: If the wrapped DEK or tag has been tampered with.
        """
        if len(kek) != self.KEY_SIZE:
            raise ValueError(f"KEK must be 32 bytes, got {len(kek)}")
        if len(wrap_nonce) != self.NONCE_SIZE:
            raise ValueError(f"Wrap nonce must be 12 bytes, got {len(wrap_nonce)}")
        if len(wrap_tag) != self.TAG_SIZE:
            raise ValueError(f"Wrap tag must be 16 bytes, got {len(wrap_tag)}")

        aesgcm = AESGCM(kek)
        combined = wrapped_dek + wrap_tag
        try:
            return aesgcm.decrypt(wrap_nonce, combined, b"envelope_dek_wrapping")
        except InvalidTag:
            raise InvalidTag("Failed to unwrap DEK: Master Key, wrap tag, or ciphertext mismatch!")

    # Backwards compatibility helper
    def derive_file_key(self, user_id: int, salt: bytes) -> bytes:
        return self.derive_kek(user_id, salt)
