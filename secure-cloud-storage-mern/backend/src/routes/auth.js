const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');

/**
 * Generates a signed JSON Web Token (JWT).
 * @param {string} userId - MongoDB User ObjectId
 * @param {string} email - User email
 * @returns {string} Signed JWT
 */
const generateToken = (userId, email) => {
  return jwt.sign(
    { userId, email },
    process.env.JWT_SECRET || 'super_secret_jwt_key_change_in_production_pbl_2026',
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

/**
 * POST /api/auth/register
 * Creates a new user account. Passwords are encrypted with bcrypt before saving.
 * Accepts optional publicKey and encryptedPrivateKey for client-side envelope sharing.
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password, publicKey, encryptedPrivateKey } = req.body;

    // 1. Validate mandatory fields
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const emailRegex = /^\S+@\S+\.\S+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters in length.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // 2. Check for duplicate account
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email address already exists.' });
    }

    // 3. Hash password using bcrypt (12 rounds)
    const passwordHash = await User.hashPassword(password);

    // 4. Save user document
    const user = new User({
      email: normalizedEmail,
      passwordHash,
      publicKey: publicKey || null,
      encryptedPrivateKey: encryptedPrivateKey || null
    });

    await user.save();

    // 5. Issue JWT session token
    const token = generateToken(user._id, user.email);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        publicKey: user.publicKey,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('[Register Error]', err);
    res.status(500).json({ error: `Registration error: ${err.message}` });
  }
});

/**
 * POST /api/auth/login
 * Authenticates user credentials via bcrypt.compare and returns a JWT session token.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find user by email
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      // Use uniform message to prevent account enumeration attacks
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Verify password against stored bcrypt hash
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Issue JWT session token
    const token = generateToken(user._id, user.email);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        publicKey: user.publicKey,
        encryptedPrivateKey: user.encryptedPrivateKey,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('[Login Error]', err);
    res.status(500).json({ error: `Login error: ${err.message}` });
  }
});

/**
 * GET /api/auth/me
 * Retrieves current authenticated user profile (protected route).
 */
router.get('/me', authMiddleware, (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      email: req.user.email,
      publicKey: req.user.publicKey,
      encryptedPrivateKey: req.user.encryptedPrivateKey,
      createdAt: req.user.createdAt
    }
  });
});

/**
 * GET /api/auth/public-key?email=recipient@example.com
 * Fetches a registered user's RSA-OAEP public key by email.
 * This public key is used by file owners to re-wrap DEKs client-side.
 * Plaintext keys or private keys are never exposed.
 */
router.get('/public-key', authMiddleware, async (req, res) => {
  try {
    const { email } = req.query;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Query parameter "email" is required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail }).select('_id email publicKey');

    if (!user) {
      return res.status(404).json({ error: `User with email "${normalizedEmail}" not found.` });
    }

    if (!user.publicKey) {
      return res.status(404).json({
        error: `User "${normalizedEmail}" has not published an RSA-OAEP public key yet. They must log in once to generate keys.`
      });
    }

    res.json({
      userId: user._id,
      email: user.email,
      publicKey: user.publicKey
    });
  } catch (err) {
    console.error('[Public Key Lookup Error]', err);
    res.status(500).json({ error: `Failed to retrieve public key: ${err.message}` });
  }
});

/**
 * POST /api/auth/public-key
 * Stores or updates the authenticated user's RSA-OAEP public key and encrypted private key.
 * Private key MUST already be encrypted client-side using the user's KEK before transmission.
 */
router.post('/public-key', authMiddleware, async (req, res) => {
  try {
    const { publicKey, encryptedPrivateKey } = req.body;

    if (!publicKey) {
      return res.status(400).json({ error: 'Public key string (SPKI Base64) is required.' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    user.publicKey = publicKey;
    if (encryptedPrivateKey) {
      user.encryptedPrivateKey = encryptedPrivateKey;
    }

    await user.save();

    res.json({
      message: 'Cryptographic public key updated successfully.',
      publicKey: user.publicKey
    });
  } catch (err) {
    console.error('[Update Public Key Error]', err);
    res.status(500).json({ error: `Failed to update public key: ${err.message}` });
  }
});

module.exports = router;
