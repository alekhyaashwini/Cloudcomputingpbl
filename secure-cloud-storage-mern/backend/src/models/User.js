const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

/**
 * User Schema
 * Represents a registered user in the Zero-Knowledge Cloud Storage system.
 * Passwords are never stored in plaintext; only salted bcrypt hashes are persisted.
 */
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email address is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address']
  },
  passwordHash: {
    type: String,
    required: [true, 'Password hash is required']
  },
  // Optional asymmetric public key (for multi-user file sharing without master password exposure)
  publicKey: {
    type: String,
    default: null
  },
  // Optional encrypted private key (wrapped with the user's master passphrase client-side)
  encryptedPrivateKey: {
    type: String,
    default: null
  },
  privateKeyIv: {
    type: String,
    default: null
  },
  privateKeySalt: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

/**
 * Compares a candidate plaintext password with the stored bcrypt passwordHash.
 * @param {string} candidatePassword - Plaintext password to verify
 * @returns {Promise<boolean>} True if match, false otherwise
 */
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.passwordHash);
};

/**
 * Helper to hash a password using bcrypt with 12 salt rounds.
 * @param {string} password - Raw password
 * @returns {Promise<string>} Hashed password string
 */
userSchema.statics.hashPassword = async function (password) {
  const salt = await bcrypt.genSalt(12);
  return await bcrypt.hash(password, salt);
};

module.exports = mongoose.model('User', userSchema);
