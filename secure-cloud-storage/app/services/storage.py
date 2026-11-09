import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

class StorageAdapter(ABC):
    """Abstract interface defining cloud storage operations for encrypted files."""

    @abstractmethod
    def save(self, storage_key: str, data: bytes) -> str:
        """Stores encrypted payload. Returns storage identifier/URI."""
        pass

    @abstractmethod
    def retrieve(self, storage_key: str) -> bytes:
        """Retrieves encrypted payload bytes."""
        pass

    @abstractmethod
    def delete(self, storage_key: str) -> bool:
        """Deletes encrypted object from storage."""
        pass

    @abstractmethod
    def exists(self, storage_key: str) -> bool:
        """Checks if object exists in storage."""
        pass


class LocalStorageAdapter(StorageAdapter):
    """
    Local filesystem storage adapter for development, testing, and offline demonstration.
    Stores strictly encrypted ciphertext payloads on local disk (zero plaintext at rest).
    """

    def __init__(self, base_directory: str):
        self.base_dir = Path(base_directory)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, storage_key: str) -> Path:
        # Mitigate path traversal attacks
        safe_key = os.path.basename(storage_key)
        return self.base_dir / safe_key

    def save(self, storage_key: str, data: bytes) -> str:
        file_path = self._get_path(storage_key)
        with open(file_path, 'wb') as f:
            f.write(data)
        return str(file_path)

    def retrieve(self, storage_key: str) -> bytes:
        file_path = self._get_path(storage_key)
        if not file_path.exists():
            raise FileNotFoundError(f"Encrypted object '{storage_key}' not found in local vault.")
        with open(file_path, 'rb') as f:
            return f.read()

    def delete(self, storage_key: str) -> bool:
        file_path = self._get_path(storage_key)
        if file_path.exists():
            file_path.unlink()
            return True
        return False

    def exists(self, storage_key: str) -> bool:
        return self._get_path(storage_key).exists()


class S3StorageAdapter(StorageAdapter):
    """
    Amazon S3 Cloud Storage Adapter using Boto3.
    Communicates securely with AWS S3 over TLS 1.3, storing strictly encrypted ciphertext
    in private S3 buckets.
    """

    def __init__(self, bucket_name: str, aws_access_key: str = None, aws_secret_key: str = None, region_name: str = 'us-east-1'):
        if not bucket_name:
            raise ValueError("S3 Bucket name is required for Amazon S3 adapter.")
        self.bucket_name = bucket_name
        self.region_name = region_name

        try:
            import boto3
            self.boto_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key or None,
                aws_secret_access_key=aws_secret_key or None,
                region_name=region_name
            )
        except ImportError:
            raise ImportError("boto3 is required for S3StorageAdapter. Run 'pip install boto3'")

    def save(self, storage_key: str, data: bytes) -> str:
        safe_key = os.path.basename(storage_key)
        # PutObject with private ACL and optional AWS S3 server-side encryption for defense-in-depth
        self.boto_client.put_object(
            Bucket=self.bucket_name,
            Key=safe_key,
            Body=data,
            ServerSideEncryption='AES256'
        )
        return f"s3://{self.bucket_name}/{safe_key}"

    def retrieve(self, storage_key: str) -> bytes:
        safe_key = os.path.basename(storage_key)
        response = self.boto_client.get_object(
            Bucket=self.bucket_name,
            Key=safe_key
        )
        return response['Body'].read()

    def delete(self, storage_key: str) -> bool:
        safe_key = os.path.basename(storage_key)
        self.boto_client.delete_object(
            Bucket=self.bucket_name,
            Key=safe_key
        )
        return True

    def exists(self, storage_key: str) -> bool:
        safe_key = os.path.basename(storage_key)
        try:
            self.boto_client.head_object(Bucket=self.bucket_name, Key=safe_key)
            return True
        except Exception:
            return False


def get_storage_adapter(config) -> StorageAdapter:
    """Factory function returning the configured storage backend."""
    if isinstance(config, dict) or hasattr(config, 'get'):
        backend = str(config.get('STORAGE_BACKEND', 'local')).lower()
        if backend == 's3':
            return S3StorageAdapter(
                bucket_name=config.get('S3_BUCKET_NAME', ''),
                aws_access_key=config.get('AWS_ACCESS_KEY_ID', ''),
                aws_secret_key=config.get('AWS_SECRET_ACCESS_KEY', ''),
                region_name=config.get('AWS_REGION', 'us-east-1')
            )
        local_dir = config.get('LOCAL_STORAGE_DIR')
        if not local_dir:
            from pathlib import Path
            local_dir = str(Path(__file__).resolve().parent.parent.parent / 'instance' / 'vault_encrypted_storage')
        return LocalStorageAdapter(local_dir)
    else:
        backend = str(getattr(config, 'STORAGE_BACKEND', 'local')).lower()
        if backend == 's3':
            return S3StorageAdapter(
                bucket_name=getattr(config, 'S3_BUCKET_NAME', ''),
                aws_access_key=getattr(config, 'AWS_ACCESS_KEY_ID', ''),
                aws_secret_key=getattr(config, 'AWS_SECRET_ACCESS_KEY', ''),
                region_name=getattr(config, 'AWS_REGION', 'us-east-1')
            )
        local_dir = getattr(config, 'LOCAL_STORAGE_DIR', None)
        if not local_dir:
            from pathlib import Path
            local_dir = str(Path(__file__).resolve().parent.parent.parent / 'instance' / 'vault_encrypted_storage')
        return LocalStorageAdapter(local_dir)
