const mongoose = require('mongoose');

/**
 * File Schema
 * Represents metadata and cryptographic parameters for a zero-knowledge encrypted file.
 * The server stores ONLY metadata; file contents reside exclusively in Amazon S3 / MinIO as ciphertext.
 */
const fileSchema = new mongoose.Schema({
  // The user who uploaded and owns the file
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Owner ID is required'],
    index: true
  },
  // Original user-provided file name (e.g. "project_report.pdf")
  originalName: {
    type: String,
    required: [true, 'Original file name is required'],
    trim: true
  },
  // Sanitized unique key in S3 / MinIO bucket (e.g. "enc_user123_a1b2c3d4.enc")
  s3Key: {
    type: String,
    required: [true, 'S3 storage key is required'],
    unique: true
  },
  // 96-bit (12-byte) AES-GCM Initialization Vector / Nonce (Hex or Base64)
  iv: {
    type: String,
    required: [true, 'Initialization vector (IV) is required']
  },
  // Envelope Encryption: Data Encryption Key (DEK) wrapped by user's Key Encryption Key (KEK)
  wrappedDEK: {
    type: String,
    required: [true, 'Wrapped Data Encryption Key (wrappedDEK) is required']
  },
  // 128-bit (16-byte) PBKDF2 salt used to derive the KEK from the user's password
  salt: {
    type: String,
    required: [true, 'PBKDF2 key derivation salt is required']
  },
  // Size of the encrypted file in bytes
  size: {
    type: Number,
    required: [true, 'File size is required'],
    min: 0
  },
  // MIME type (e.g. "application/pdf", "image/png")
  mimeType: {
    type: String,
    default: 'application/octet-stream'
  },
  // Access Control: List of users this file has been shared with via envelope re-wrapping
  sharedWith: [
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
      },
      // The file's DEK re-wrapped with the recipient's public key or shared KEK
      wrappedDEK: {
        type: String,
        required: true
      },
      sharedAt: {
        type: Date,
        default: Date.now
      }
    }
  ],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index to quickly query files shared with a specific user
fileSchema.index({ 'sharedWith.userId': 1 });

module.exports = mongoose.model('File', fileSchema);
