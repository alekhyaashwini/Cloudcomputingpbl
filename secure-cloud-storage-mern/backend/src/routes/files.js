const express = require('express');
const router = express.Router();
const multer = require('multer');
const crypto = require('crypto');
const File = require('../models/File');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const { storageService, BUCKET_NAME } = require('../config/s3');

// Configure Multer for in-memory buffer handling (50MB maximum upload limit)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB
  }
});

// Protect all file routes with JWT authentication
router.use(authMiddleware);

/**
 * GET /api/files
 * Lists the authenticated user's uploaded and shared files (metadata only, no content).
 */
router.get('/', async (req, res) => {
  try {
    const userId = req.user._id;

    // Retrieve files owned by user or shared with user
    const files = await File.find({
      $or: [
        { ownerId: userId },
        { 'sharedWith.userId': userId }
      ]
    })
      .select('-__v')
      .populate('ownerId', 'email')
      .sort({ createdAt: -1 });

    res.json({ files });
  } catch (err) {
    console.error('[List Files Error]', err);
    res.status(500).json({ error: `Failed to retrieve files: ${err.message}` });
  }
});

/**
 * POST /api/files/upload
 * Accepts multipart/form-data with encrypted blob + envelope metadata (iv, wrappedDEK, salt, originalName, mimeType).
 * Stores raw ciphertext blob in Amazon S3 / MinIO and metadata in MongoDB.
 * Plaintext is never received, processed, or logged.
 */
router.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const {
      originalName,
      iv,
      wrappedDEK,
      salt,
      mimeType,
      size
    } = req.body;

    // Extract binary ciphertext buffer from multipart upload or base64 fallback
    let ciphertextBuffer = null;
    if (req.file && req.file.buffer) {
      ciphertextBuffer = req.file.buffer;
    } else if (req.body.ciphertextBase64 || req.body.base64Ciphertext) {
      ciphertextBuffer = Buffer.from(req.body.ciphertextBase64 || req.body.base64Ciphertext, 'base64');
    }

    if (!ciphertextBuffer) {
      return res.status(400).json({
        error: 'Missing file payload. Please attach the encrypted file blob in the multipart form field "file".'
      });
    }

    // Validate envelope encryption cryptographic parameters
    if (!iv || !wrappedDEK || !salt) {
      return res.status(400).json({
        error: 'Missing cryptographic envelope parameters. Both "iv", "wrappedDEK", and "salt" are required for zero-knowledge decryption.'
      });
    }

    const fileName = (originalName || req.file?.originalname || 'unnamed_encrypted_file').trim();
    const resolvedMimeType = mimeType || req.file?.mimetype || 'application/octet-stream';
    const fileSize = Number(size) || ciphertextBuffer.length;

    // Generate randomized, safe S3 storage key (protects against path traversal attacks)
    const randomSuffix = crypto.randomBytes(8).toString('hex');
    const s3Key = `enc_${req.user._id}_${Date.now()}_${randomSuffix}.enc`;

    // 1. Upload raw ciphertext buffer to S3 / MinIO bucket
    await storageService.uploadCiphertext(s3Key, ciphertextBuffer, resolvedMimeType);

    // 2. Persist metadata document in MongoDB
    const fileDoc = new File({
      ownerId: req.user._id,
      originalName: fileName,
      s3Key,
      iv: iv.trim(),
      wrappedDEK: wrappedDEK.trim(),
      salt: salt.trim(),
      size: fileSize,
      mimeType: resolvedMimeType,
      sharedWith: []
    });

    await fileDoc.save();

    console.log(`[Zero-Knowledge] Uploaded "${fileName}" -> s3://${BUCKET_NAME}/${s3Key} (${fileSize} bytes). Zero plaintext seen.`);

    res.status(201).json({
      message: 'File successfully encrypted and stored in cloud object storage.',
      file: {
        id: fileDoc._id,
        originalName: fileDoc.originalName,
        s3Key: fileDoc.s3Key,
        iv: fileDoc.iv,
        wrappedDEK: fileDoc.wrappedDEK,
        salt: fileDoc.salt,
        size: fileDoc.size,
        mimeType: fileDoc.mimeType,
        createdAt: fileDoc.createdAt
      }
    });
  } catch (err) {
    console.error('[Upload Error]', err);
    res.status(500).json({ error: `Upload failed: ${err.message}` });
  }
});

/**
 * GET /api/files/:id/download
 * Retrieves an encrypted file.
 * Query Options:
 *   ?presigned=true -> Returns a temporary pre-signed S3 download URL valid for 1 hour.
 *   (default)       -> Streams the raw ciphertext binary directly to the browser.
 */
router.get('/:id/download', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ error: 'File not found in storage index.' });
    }

    // Access Control & Tenant Isolation Check
    const userId = req.user._id.toString();
    const isOwner = file.ownerId.toString() === userId;
    const sharedEntry = file.sharedWith.find(s => s.userId.toString() === userId);

    if (!isOwner && !sharedEntry) {
      return res.status(403).json({
        error: 'Access Denied: You do not have permission to access this file.'
      });
    }

    // If client requested a pre-signed S3 URL
    if (req.query.presigned === 'true' || req.query.presigned === '1') {
      const presignedUrl = await storageService.getPresignedDownloadUrl(file.s3Key, 3600);
      return res.json({
        downloadUrl: presignedUrl,
        expiresInSeconds: 3600,
        metadata: {
          id: file._id,
          originalName: file.originalName,
          mimeType: file.mimeType,
          size: file.size,
          iv: file.iv,
          // Return recipient-specific wrapped DEK if shared, otherwise owner wrapped DEK
          wrappedDEK: sharedEntry ? sharedEntry.wrappedDEK : file.wrappedDEK,
          salt: file.salt
        }
      });
    }

    // If client prefers JSON envelope payload (Base64)
    if (req.headers.accept?.includes('application/json')) {
      const ciphertextBuffer = await storageService.getCiphertext(file.s3Key);
      return res.json({
        id: file._id,
        originalName: file.originalName,
        mimeType: file.mimeType,
        size: file.size,
        iv: file.iv,
        wrappedDEK: sharedEntry ? sharedEntry.wrappedDEK : file.wrappedDEK,
        salt: file.salt,
        base64Ciphertext: ciphertextBuffer.toString('base64')
      });
    }

    // Default: Stream ciphertext binary stream directly to client
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}.enc"`);
    res.setHeader('Content-Length', file.size);
    res.setHeader('X-File-IV', file.iv);
    res.setHeader('X-Wrapped-DEK', sharedEntry ? sharedEntry.wrappedDEK : file.wrappedDEK);
    res.setHeader('X-File-Salt', file.salt);
    res.setHeader('X-Original-Name', encodeURIComponent(file.originalName));

    const stream = await storageService.getCiphertextStream(file.s3Key);
    stream.pipe(res);
  } catch (err) {
    console.error('[Download Error]', err);
    res.status(500).json({ error: `Download failed: ${err.message}` });
  }
});

/**
 * DELETE /api/files/:id
 * Deletes the encrypted ciphertext object from Amazon S3 / MinIO and removes metadata from MongoDB.
 * Enforces strict file ownership.
 */
router.delete('/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ error: 'File not found.' });
    }

    // Only the file owner can delete the file
    if (file.ownerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access Denied: Only the file owner is permitted to delete this file.'
      });
    }

    // 1. Delete object from S3 / MinIO
    try {
      await storageService.deleteObject(file.s3Key);
    } catch (s3Err) {
      console.warn(`[Delete Warning] S3 key "${file.s3Key}" could not be deleted from bucket: ${s3Err.message}`);
    }

    // 2. Remove metadata record from MongoDB
    await File.findByIdAndDelete(req.params.id);

    console.log(`[Zero-Knowledge] Deleted file "${file.originalName}" (${file.s3Key}) for user ${req.user._id}`);

    res.json({
      message: 'File and cloud object successfully deleted.',
      id: req.params.id
    });
  } catch (err) {
    console.error('[Delete Error]', err);
    res.status(500).json({ error: `Delete failed: ${err.message}` });
  }
});

/**
 * GET /api/files/shared-with-me
 * Retrieves list of files shared with the currently authenticated user.
 */
router.get('/shared/shared-with-me', async (req, res) => {
  try {
    const userId = req.user._id;
    const files = await File.find({ 'sharedWith.userId': userId })
      .select('-__v')
      .populate('ownerId', 'email')
      .sort({ createdAt: -1 });

    // Format response to include recipient-specific wrapped DEK
    const formatted = files.map(file => {
      const shareEntry = file.sharedWith.find(s => s.userId.toString() === userId.toString());
      return {
        id: file._id,
        originalName: file.originalName,
        size: file.size,
        mimeType: file.mimeType,
        createdAt: file.createdAt,
        ownerEmail: file.ownerId ? file.ownerId.email : 'Unknown',
        sharedAt: shareEntry ? shareEntry.sharedAt : file.createdAt,
        iv: file.iv,
        wrappedDEK: shareEntry ? shareEntry.wrappedDEK : null
      };
    });

    res.json({ files: formatted });
  } catch (err) {
    console.error('[Shared-With-Me Error]', err);
    res.status(500).json({ error: `Failed to fetch shared files: ${err.message}` });
  }
});

/**
 * POST /api/files/:id/share
 * Enables zero-knowledge file sharing between users via asymmetric RSA-OAEP key wrapping.
 * 
 * Flow:
 * 1. Owner's browser unwraps the file's DEK using owner's password-derived KEK.
 * 2. Owner's browser re-wraps the DEK using the recipient's RSA-OAEP public key.
 * 3. Client calls this endpoint with { recipientEmail, wrappedDEK }.
 * 4. The server validates ownership and stores the re-wrapped DEK in the file's sharedWith array.
 * 
 * Cryptographic Zero-Knowledge Invariant:
 * The server NEVER sees the plaintext DEK or the file content.
 * Only the recipient with their matching private key can unwrap this DEK.
 */
router.post('/:id/share', async (req, res) => {
  try {
    const { recipientEmail, wrappedDEK } = req.body;
    const fileId = req.params.id;

    if (!recipientEmail || typeof recipientEmail !== 'string') {
      return res.status(400).json({ error: 'recipientEmail is required in request body.' });
    }

    const normalizedEmail = recipientEmail.trim().toLowerCase();

    // 1. Locate the target file
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found in storage registry.' });
    }

    // 2. Enforce strict ownership: Only the file owner can grant access
    if (file.ownerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access Denied: Only the file owner is authorized to share this file.'
      });
    }

    // 3. Locate recipient user
    const recipientUser = await User.findOne({ email: normalizedEmail });
    if (!recipientUser) {
      return res.status(404).json({
        error: `Recipient user with email "${normalizedEmail}" is not registered on this system.`
      });
    }

    // 4. Prevent self-sharing
    if (recipientUser._id.toString() === req.user._id.toString()) {
      return res.status(400).json({
        error: 'Invalid Operation: You cannot share a file with your own account.'
      });
    }

    // 5. Ensure recipient has an active public key
    if (!recipientUser.publicKey) {
      return res.status(400).json({
        error: `Recipient "${normalizedEmail}" has not published an RSA-OAEP public key yet. They must log in once to initialize their key pair.`
      });
    }

    // Handshake mode: If client requested recipient info before re-wrapping
    if (!wrappedDEK) {
      return res.status(200).json({
        message: 'Recipient public key located. Perform client-side re-wrapping with this key and re-submit with wrappedDEK.',
        recipient: {
          id: recipientUser._id,
          email: recipientUser.email,
          publicKey: recipientUser.publicKey
        },
        fileParameters: {
          id: file._id,
          iv: file.iv,
          salt: file.salt,
          wrappedDEK: file.wrappedDEK
        }
      });
    }

    // 6. Update or insert the recipient's re-wrapped DEK in sharedWith array
    const existingIndex = file.sharedWith.findIndex(
      s => s.userId.toString() === recipientUser._id.toString()
    );

    if (existingIndex >= 0) {
      // Update existing share entry
      file.sharedWith[existingIndex].wrappedDEK = wrappedDEK.trim();
      file.sharedWith[existingIndex].sharedAt = new Date();
    } else {
      // Add new share entry
      file.sharedWith.push({
        userId: recipientUser._id,
        wrappedDEK: wrappedDEK.trim(),
        sharedAt: new Date()
      });
    }

    await file.save();

    console.log(
      `[Zero-Knowledge Sharing] File "${file.originalName}" shared by ${req.user.email} ` +
      `with ${recipientUser.email}. Stored re-wrapped DEK (${wrappedDEK.length} chars).`
    );

    res.status(200).json({
      message: `File "${file.originalName}" successfully shared with ${recipientUser.email}.`,
      fileId: file._id,
      recipient: {
        id: recipientUser._id,
        email: recipientUser.email
      },
      sharedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[Share Error]', err);
    res.status(500).json({ error: `Failed to share file: ${err.message}` });
  }
});

/**
 * DELETE /api/files/:id/share/:recipientId
 * Revokes file access for a specific recipient.
 * 
 * Note on Revocation Security:
 * Removing the recipient from sharedWith prevents the server from returning the ciphertext or re-wrapped DEK.
 * However, because the recipient may have previously cached the DEK, true cryptographic revocation
 * requires re-encrypting the ciphertext in S3 with a fresh DEK (see security analysis).
 */
router.delete('/:id/share/:recipientId', async (req, res) => {
  try {
    const { id: fileId, recipientId } = req.params;

    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found.' });
    }

    if (file.ownerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access Denied: Only the owner can revoke sharing.' });
    }

    // Filter out recipient
    const originalCount = file.sharedWith.length;
    file.sharedWith = file.sharedWith.filter(
      s => s.userId.toString() !== recipientId && s._id?.toString() !== recipientId
    );

    if (file.sharedWith.length === originalCount) {
      return res.status(404).json({ error: 'Recipient share entry not found.' });
    }

    await file.save();

    res.json({
      message: 'Access revoked successfully. Recipient can no longer download ciphertext or wrapped DEK.',
      fileId: file._id
    });
  } catch (err) {
    console.error('[Revoke Share Error]', err);
    res.status(500).json({ error: `Failed to revoke share: ${err.message}` });
  }
});

module.exports = router;

