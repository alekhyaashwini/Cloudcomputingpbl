import sqlite3
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Optional, List, Dict, Any, Tuple

class Database:
    """
    SQLite Database Access Layer with parameterized SQL queries.
    Enforces referential integrity, unique constraints, and schema migrations.
    Supports in-memory testing with persistent shared connection.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._shared_conn = None
        if db_path != ':memory:':
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        else:
            self._shared_conn = sqlite3.connect(':memory:', check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
            self._shared_conn.execute("PRAGMA foreign_keys = ON")
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self):
        """Creates tables with proper constraints."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Files Metadata Table with Envelope Encryption & SHA-256 Digest
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    original_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    original_size INTEGER NOT NULL,
                    encrypted_size INTEGER NOT NULL,
                    storage_backend TEXT NOT NULL,
                    storage_key TEXT NOT NULL UNIQUE,
                    file_nonce_hex TEXT NOT NULL,
                    file_auth_tag_hex TEXT NOT NULL,
                    wrapped_dek_hex TEXT NOT NULL,
                    wrap_nonce_hex TEXT NOT NULL,
                    wrap_auth_tag_hex TEXT NOT NULL,
                    salt_hex TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')

            # File Shares Table with Expiration and Revocation support
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL,
                    owner_id INTEGER NOT NULL,
                    shared_with_user_id INTEGER NOT NULL,
                    permission TEXT DEFAULT 'read_download',
                    expires_at TIMESTAMP NULL,
                    is_revoked INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(file_id, shared_with_user_id)
                )
            ''')

            # Audit Logs Table for Security Monitoring
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    event_type TEXT NOT NULL,
                    details TEXT NOT NULL,
                    ip_address TEXT,
                    status TEXT DEFAULT 'SUCCESS',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                )
            ''')
            conn.commit()

    # User operations
    def create_user(self, username: str, email: str, password: str) -> Optional[int]:
        password_hash = generate_password_hash(password)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username.strip(), email.strip().lower(), password_hash)
                )
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        clean = identifier.strip().lower()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
                (clean, clean)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def verify_password(self, stored_hash: str, password: str) -> bool:
        return check_password_hash(stored_hash, password)

    # File operations with Envelope Encryption
    def create_file(self, owner_id: int, original_name: str, mime_type: str,
                    original_size: int, encrypted_size: int, storage_backend: str,
                    storage_key: str, file_nonce_hex: str, file_auth_tag_hex: str,
                    wrapped_dek_hex: str, wrap_nonce_hex: str, wrap_auth_tag_hex: str,
                    salt_hex: str, key_id: str, sha256_hash: str) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (
                    owner_id, original_name, mime_type, original_size, encrypted_size,
                    storage_backend, storage_key, file_nonce_hex, file_auth_tag_hex,
                    wrapped_dek_hex, wrap_nonce_hex, wrap_auth_tag_hex,
                    salt_hex, key_id, sha256_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                owner_id, original_name, mime_type, original_size, encrypted_size,
                storage_backend, storage_key, file_nonce_hex, file_auth_tag_hex,
                wrapped_dek_hex, wrap_nonce_hex, wrap_auth_tag_hex,
                salt_hex, key_id, sha256_hash
            ))
            conn.commit()
            return cursor.lastrowid

    def get_user_files(self, owner_id: int) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC",
                (owner_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_file_by_id(self, file_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def delete_file(self, file_id: int, owner_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM files WHERE id = ? AND owner_id = ?",
                (file_id, owner_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    # File Sharing Operations with Expiration & Revocation
    def share_file(self, file_id: int, owner_id: int, recipient_identifier: str,
                   duration_hours: Optional[int] = None, permission: str = 'read_download') -> Tuple[bool, str]:
        """Shares a file with another user by username or email with optional expiration."""
        recipient = self.get_user_by_identifier(recipient_identifier)
        if not recipient:
            return False, f"User '{recipient_identifier}' not found."
        
        if recipient['id'] == owner_id:
            return False, "You already own this file."

        file_rec = self.get_file_by_id(file_id)
        if not file_rec or file_rec['owner_id'] != owner_id:
            return False, "You do not own this file or it does not exist."

        expires_at_str = None
        if duration_hours and duration_hours > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
            expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')

        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                # Update existing share if present or insert fresh
                cursor.execute('''
                    INSERT INTO file_shares (file_id, owner_id, shared_with_user_id, permission, expires_at, is_revoked)
                    VALUES (?, ?, ?, ?, ?, 0)
                    ON CONFLICT(file_id, shared_with_user_id) DO UPDATE SET
                        permission=excluded.permission,
                        expires_at=excluded.expires_at,
                        is_revoked=0,
                        created_at=CURRENT_TIMESTAMP
                ''', (file_id, owner_id, recipient['id'], permission, expires_at_str))
                conn.commit()
                expiry_msg = f" (Expires: {expires_at_str} UTC)" if expires_at_str else " (No Expiration)"
                return True, f"File successfully shared with {recipient['username']}{expiry_msg}."
            except Exception as e:
                return False, f"Sharing error: {str(e)}"

    def get_shares_for_file(self, file_id: int, owner_id: int) -> List[Dict[str, Any]]:
        """Returns all shares for a file owned by owner_id."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT fs.id as share_id, fs.permission, fs.expires_at, fs.is_revoked, fs.created_at,
                       u.id as user_id, u.username, u.email
                FROM file_shares fs
                JOIN users u ON fs.shared_with_user_id = u.id
                WHERE fs.file_id = ? AND fs.owner_id = ?
                ORDER BY fs.created_at DESC
            ''', (file_id, owner_id))
            return [dict(row) for row in cursor.fetchall()]

    def get_shared_files_for_user(self, user_id: int) -> List[Dict[str, Any]]:
        """Returns active, non-expired, non-revoked files shared with this user."""
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT f.*, u.username as owner_username, fs.id as share_id,
                       fs.permission, fs.expires_at, fs.created_at as shared_at
                FROM file_shares fs
                JOIN files f ON fs.file_id = f.id
                JOIN users u ON fs.owner_id = u.id
                WHERE fs.shared_with_user_id = ?
                  AND fs.is_revoked = 0
                  AND (fs.expires_at IS NULL OR fs.expires_at > ?)
                ORDER BY fs.created_at DESC
            ''', (user_id, now_str))
            return [dict(row) for row in cursor.fetchall()]

    def revoke_share(self, share_id: int, owner_id: int) -> bool:
        """Revokes a share immediately."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE file_shares SET is_revoked = 1 WHERE id = ? AND owner_id = ?",
                (share_id, owner_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def can_user_access_file(self, file_id: int, user_id: int) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Determines whether user_id can access file_id.
        Enforces ownership, non-revocation, and non-expiration.
        Returns: (has_access: bool, access_type: 'owner'|'shared'|'expired'|'revoked'|'denied'|'not_found', file_record)
        """
        file_rec = self.get_file_by_id(file_id)
        if not file_rec:
            return False, 'not_found', None

        if file_rec['owner_id'] == user_id:
            return True, 'owner', file_rec

        # Check share
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, is_revoked, expires_at FROM file_shares WHERE file_id = ? AND shared_with_user_id = ?",
                (file_id, user_id)
            )
            share_row = cursor.fetchone()
            if not share_row:
                return False, 'denied', None

            if share_row['is_revoked']:
                return False, 'revoked', None

            if share_row['expires_at'] and share_row['expires_at'] <= now_str:
                return False, 'expired', None

            return True, 'shared', file_rec

    # Audit Logging Operations
    def log_event(self, user_id: Optional[int], username: Optional[str],
                  event_type: str, details: str, ip_address: Optional[str] = None,
                  status: str = 'SUCCESS'):
        """Appends an event to the security audit trail."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO audit_logs (user_id, username, event_type, details, ip_address, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, username or 'Anonymous', event_type, details, ip_address or '127.0.0.1', status))
                conn.commit()
        except Exception:
            pass

    def get_audit_logs(self, user_id: Optional[int] = None, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves recent audit log events."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM audit_logs"
            params = []
            conditions = []
            
            if user_id is not None:
                conditions.append("user_id = ?")
                params.append(user_id)
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]
