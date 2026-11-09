import os
import io
import uuid
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    session, current_app, send_file, abort, jsonify
)
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag
from app.auth.routes import login_required, get_client_ip
from app.services.encryption import CryptographicService

files_bp = Blueprint('files', __name__, url_prefix='/files')

@files_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    files = current_app.db.get_user_files(user_id)
    shared_files = current_app.db.get_shared_files_for_user(user_id)
    total_size = sum(f['original_size'] for f in files)
    total_encrypted_size = sum(f['encrypted_size'] for f in files)
    storage_backend = current_app.config['STORAGE_BACKEND'].upper()

    return render_template(
        'dashboard.html',
        files=files,
        shared_count=len(shared_files),
        total_files=len(files),
        total_size=total_size,
        total_encrypted_size=total_encrypted_size,
        storage_backend=storage_backend,
        username=session.get('username')
    )

@files_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    user_id = session['user_id']
    username = session.get('username', 'User')

    if 'file' not in request.files:
        flash('No file selected for upload.', 'danger')
        return redirect(url_for('files.dashboard'))

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        flash('Please choose a file to upload.', 'danger')
        return redirect(url_for('files.dashboard'))

    safe_original_name = secure_filename(uploaded_file.filename)
    if not safe_original_name:
        safe_original_name = f"vault_file_{uuid.uuid4().hex[:8]}"

    plaintext_bytes = uploaded_file.read()
    original_size = len(plaintext_bytes)

    if original_size > current_app.config['MAX_CONTENT_LENGTH']:
        limit_mb = current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        flash(f'File exceeds maximum limit of {limit_mb}MB.', 'danger')
        return redirect(url_for('files.dashboard'))

    try:
        # 1. Plaintext Integrity: Compute SHA-256 fingerprint
        sha256_hash = CryptographicService.compute_sha256(plaintext_bytes)

        # 2. Envelope Encryption - Step A: Generate unique 256-bit DEK
        dek = current_app.key_service.generate_dek()

        # 3. Envelope Encryption - Step B: Encrypt file content with DEK via AES-256-GCM
        ciphertext, file_nonce, file_auth_tag = CryptographicService.encrypt(plaintext_bytes, dek)

        # 4. Envelope Encryption - Step C: Derive tenant-isolated KEK via PBKDF2 (100k rounds)
        salt = current_app.key_service.generate_salt()
        kek = current_app.key_service.derive_kek(user_id, salt)

        # 5. Envelope Encryption - Step D: Wrap DEK with KEK via AES-256-GCM
        wrapped_dek, wrap_nonce, wrap_auth_tag = current_app.key_service.wrap_dek(dek, kek)

        # Discard plaintext DEK from local scope immediately
        del dek

        # 6. Store encrypted payload in storage backend (Local Vault or Amazon S3)
        storage_key = f"{uuid.uuid4().hex}_{safe_original_name}.enc"
        current_app.storage_adapter.save(storage_key, ciphertext)

        # 7. Persist cryptographic metadata in SQLite
        current_app.db.create_file(
            owner_id=user_id,
            original_name=safe_original_name,
            mime_type=uploaded_file.mimetype or 'application/octet-stream',
            original_size=original_size,
            encrypted_size=len(ciphertext),
            storage_backend=current_app.config['STORAGE_BACKEND'],
            storage_key=storage_key,
            file_nonce_hex=file_nonce.hex(),
            file_auth_tag_hex=file_auth_tag.hex(),
            wrapped_dek_hex=wrapped_dek.hex(),
            wrap_nonce_hex=wrap_nonce.hex(),
            wrap_auth_tag_hex=wrap_auth_tag.hex(),
            salt_hex=salt.hex(),
            key_id=current_app.key_service.KEY_VERSION,
            sha256_hash=sha256_hash
        )

        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='FILE_UPLOAD_ENCRYPTED',
            details=f'Envelope encrypted "{safe_original_name}" ({original_size}B -> {len(ciphertext)}B) using AES-256-GCM to {current_app.config["STORAGE_BACKEND"].upper()}',
            ip_address=get_client_ip(),
            status='SUCCESS'
        )

        flash(
            f'File "{safe_original_name}" encrypted using Envelope Encryption (AES-256-GCM DEK + Wrapped KEK) '
            f'and stored in {current_app.config["STORAGE_BACKEND"].upper()} storage!',
            'success'
        )
    except Exception as e:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='FILE_UPLOAD_FAILED',
            details=f'Upload/encryption failed for "{safe_original_name}": {str(e)}',
            ip_address=get_client_ip(),
            status='ERROR'
        )
        flash(f'Encryption or storage error: {str(e)}', 'danger')

    return redirect(url_for('files.dashboard'))

@files_bp.route('/download/<int:file_id>')
@login_required
def download(file_id):
    user_id = session['user_id']
    username = session.get('username', 'User')

    has_access, access_type, file_record = current_app.db.can_user_access_file(file_id, user_id)

    if access_type == 'not_found':
        flash('File not found.', 'danger')
        return redirect(url_for('files.dashboard'))

    if access_type == 'expired':
        flash('Access Denied: The share link for this file has expired.', 'warning')
        abort(403)

    if access_type == 'revoked':
        flash('Access Denied: Sharing access for this file has been revoked by the owner.', 'danger')
        abort(403)

    if not has_access:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='UNAUTHORIZED_ACCESS_ATTEMPT',
            details=f'Unauthorized download attempt on file ID #{file_id}',
            ip_address=get_client_ip(),
            status='SECURITY_ALERT'
        )
        flash('Access Denied: You do not have permission to access this file.', 'danger')
        abort(403)

    try:
        # Retrieve encrypted ciphertext from storage adapter
        ciphertext = current_app.storage_adapter.retrieve(file_record['storage_key'])

        # 1. Derive owner's KEK
        owner_id = file_record['owner_id']
        salt = bytes.fromhex(file_record['salt_hex'])
        kek = current_app.key_service.derive_kek(owner_id, salt)

        # 2. Unwrap DEK using KEK
        wrapped_dek = bytes.fromhex(file_record['wrapped_dek_hex'])
        wrap_nonce = bytes.fromhex(file_record['wrap_nonce_hex'])
        wrap_auth_tag = bytes.fromhex(file_record['wrap_auth_tag_hex'])
        dek = current_app.key_service.unwrap_dek(wrapped_dek, wrap_nonce, wrap_auth_tag, kek)

        # 3. Decrypt ciphertext using DEK and verify GHASH Authentication Tag
        file_nonce = bytes.fromhex(file_record['file_nonce_hex'])
        file_auth_tag = bytes.fromhex(file_record['file_auth_tag_hex'])
        decrypted_bytes = CryptographicService.decrypt(ciphertext, file_nonce, file_auth_tag, dek)

        # 4. Plaintext Integrity Check: Verify SHA-256 fingerprint
        recomputed_hash = CryptographicService.compute_sha256(decrypted_bytes)
        if recomputed_hash != file_record['sha256_hash']:
            raise InvalidTag("SHA-256 Plaintext digest mismatch! Cryptographic corruption detected.")

        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='FILE_DOWNLOAD_DECRYPTED',
            details=f'Successfully decrypted and verified "{file_record["original_name"]}" (Access: {access_type})',
            ip_address=get_client_ip(),
            status='SUCCESS'
        )

        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=file_record['mime_type'],
            as_attachment=True,
            download_name=file_record['original_name']
        )
    except InvalidTag as it:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='INTEGRITY_VIOLATION_TAMPERING',
            details=f'CRITICAL: AES-GCM Auth tag or SHA-256 mismatch on file "{file_record["original_name"]}". Ciphertext tampered or corrupted!',
            ip_address=get_client_ip(),
            status='SECURITY_ALERT'
        )
        flash(
            'SECURITY ALERT: Cryptographic Authentication Tag Mismatch! '
            'The ciphertext has been corrupted or tampered with. Decryption rejected.',
            'danger'
        )
        return redirect(url_for('files.dashboard'))
    except Exception as e:
        flash(f'Error retrieving or decrypting file: {str(e)}', 'danger')
        return redirect(url_for('files.dashboard'))

@files_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    user_id = session['user_id']
    username = session.get('username', 'User')
    file_record = current_app.db.get_file_by_id(file_id)

    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('files.dashboard'))

    # Security: Verify ownership (Only file owner can delete)
    if file_record['owner_id'] != user_id:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='UNAUTHORIZED_DELETE_ATTEMPT',
            details=f'Unauthorized attempt to delete file #{file_id} owned by user #{file_record["owner_id"]}',
            ip_address=get_client_ip(),
            status='SECURITY_ALERT'
        )
        flash('Access Denied: You cannot delete files belonging to other users.', 'danger')
        abort(403)

    try:
        # Delete from storage backend
        current_app.storage_adapter.delete(file_record['storage_key'])
        # Delete metadata from database
        current_app.db.delete_file(file_id, user_id)
        
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='FILE_DELETED',
            details=f'Deleted file "{file_record["original_name"]}" and purged encrypted cloud object {file_record["storage_key"]}',
            ip_address=get_client_ip(),
            status='SUCCESS'
        )
        flash(f'File "{file_record["original_name"]}" and its encrypted cloud object were securely deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')

    return redirect(url_for('files.dashboard'))

@files_bp.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share(file_id):
    user_id = session['user_id']
    username = session.get('username', 'User')
    recipient_identifier = request.form.get('recipient', '').strip()
    duration_hours_str = request.form.get('duration_hours', '0').strip()

    try:
        duration_hours = int(duration_hours_str) if duration_hours_str else None
    except ValueError:
        duration_hours = None

    if not recipient_identifier:
        flash('Please specify a username or email to share with.', 'warning')
        return redirect(url_for('files.dashboard'))

    success, msg = current_app.db.share_file(
        file_id=file_id,
        owner_id=user_id,
        recipient_identifier=recipient_identifier,
        duration_hours=duration_hours,
        permission='read_download'
    )
    if success:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='FILE_SHARED',
            details=f'Shared file #{file_id} with "{recipient_identifier}" (Duration: {duration_hours}h)',
            ip_address=get_client_ip(),
            status='SUCCESS'
        )
        flash(msg, 'success')
    else:
        flash(msg, 'danger')

    return redirect(url_for('files.dashboard'))

@files_bp.route('/shared')
@login_required
def shared_files():
    user_id = session['user_id']
    shared_files = current_app.db.get_shared_files_for_user(user_id)
    return render_template('shared_files.html', shared_files=shared_files)

@files_bp.route('/shares/<int:file_id>')
@login_required
def manage_shares(file_id):
    user_id = session['user_id']
    file_record = current_app.db.get_file_by_id(file_id)
    if not file_record or file_record['owner_id'] != user_id:
        flash('File not found or access denied.', 'danger')
        return redirect(url_for('files.dashboard'))
    
    shares = current_app.db.get_shares_for_file(file_id, user_id)
    return render_template('manage_shares.html', file=file_record, shares=shares)

@files_bp.route('/revoke_share/<int:share_id>', methods=['POST'])
@login_required
def revoke_share(share_id):
    user_id = session['user_id']
    username = session.get('username', 'User')
    file_id = request.form.get('file_id')
    success = current_app.db.revoke_share(share_id, user_id)
    if success:
        current_app.db.log_event(
            user_id=user_id,
            username=username,
            event_type='SHARE_REVOKED',
            details=f'Revoked sharing permission ID #{share_id} on file #{file_id}',
            ip_address=get_client_ip(),
            status='INFO'
        )
        flash('File sharing permission has been revoked.', 'info')
    else:
        flash('Could not revoke sharing permission.', 'danger')
        
    if file_id:
        return redirect(url_for('files.manage_shares', file_id=file_id))
    return redirect(url_for('files.dashboard'))

@files_bp.route('/details/<int:file_id>')
@login_required
def file_details(file_id):
    """API endpoint returning safe cryptographic metadata for verification."""
    user_id = session['user_id']
    has_access, access_type, file_record = current_app.db.can_user_access_file(file_id, user_id)
    if not has_access:
        return jsonify({'error': 'Unauthorized'}), 403

    safe_metadata = {
        'id': file_record['id'],
        'original_name': file_record['original_name'],
        'mime_type': file_record['mime_type'],
        'original_size_bytes': file_record['original_size'],
        'encrypted_size_bytes': file_record['encrypted_size'],
        'storage_backend': file_record['storage_backend'],
        'storage_key': file_record['storage_key'],
        'cipher': 'AES-256-GCM (AEAD)',
        'file_nonce_hex': file_record['file_nonce_hex'],
        'file_auth_tag_hex': file_record['file_auth_tag_hex'],
        'wrapped_dek_preview': file_record['wrapped_dek_hex'][:24] + '...',
        'wrap_nonce_hex': file_record['wrap_nonce_hex'],
        'sha256_hash': file_record['sha256_hash'],
        'key_id': file_record['key_id'],
        'created_at': file_record['created_at'],
        'access_type': access_type
    }
    return jsonify(safe_metadata)
