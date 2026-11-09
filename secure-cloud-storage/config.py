import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-flask-session-secret-change-me')
    
    # SQLite database location in instance directory
    DATABASE_PATH = os.environ.get('DATABASE_PATH', str(BASE_DIR / 'instance' / 'secure_vault.sqlite'))
    
    # Master Key for derivation: 32 bytes minimum
    MASTER_ENCRYPTION_KEY = os.environ.get(
        'MASTER_ENCRYPTION_KEY', 
        'college_pbl_aes256gcm_master_key_secret_2026_demo_key'
    )
    
    # Storage adapter selection
    STORAGE_BACKEND = os.environ.get('STORAGE_BACKEND', 'local').lower()
    LOCAL_STORAGE_DIR = os.environ.get('LOCAL_STORAGE_DIR', str(BASE_DIR / 'instance' / 'vault_encrypted_storage'))
    
    # AWS S3 Settings
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', '')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', '')
    
    # Upload limits: 25 Megabytes
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 25 * 1024 * 1024))
    
    # Session Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # In local development HTTP is used; set to True in HTTPS production
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'

class TestingConfig(Config):
    """Testing configuration with in-memory or temporary paths."""
    TESTING = True
    DATABASE_PATH = ':memory:'
    STORAGE_BACKEND = 'local'
