const express = require('express');
const router = express.Router();
const User = require('../models/User');
const File = require('../models/File');
const authenticateToken = require('../middleware/auth');

/**
 * GET /api/users/keys
 * Protected route to fetch current user's RSA-OAEP public key and encrypted private key status.
 */
router.get('/keys', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('publicKey encryptedPrivateKey privateKeyIv privateKeySalt');
    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    res.json({
      publicKey: user.publicKey || null,
      encryptedPrivateKey: user.encryptedPrivateKey || null,
      privateKeyIv: user.privateKeyIv || null,
      privateKeySalt: user.privateKeySalt || null,
      hasKeyPair: Boolean(user.publicKey && user.encryptedPrivateKey)
    });
  } catch (err) {
    console.error('Fetch keys error:', err);
    res.status(500).json({ error: 'Failed to retrieve user key status.' });
  }
});

/**
 * PUT /api/users/keys
 * Protected route to save or update the user's RSA-OAEP sharing key pair.
 * The public key is stored in SPKI format; the private key is stored encrypted with the user's KEK.
 */
router.put('/keys', authenticateToken, async (req, res) => {
  try {
    const { publicKey, encryptedPrivateKey, privateKeyIv, privateKeySalt } = req.body;

    if (!publicKey) {
      return res.status(400).json({ error: 'publicKey string is required.' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    user.publicKey = publicKey;
    if (encryptedPrivateKey) user.encryptedPrivateKey = encryptedPrivateKey;
    if (privateKeyIv) user.privateKeyIv = privateKeyIv;
    if (privateKeySalt) user.privateKeySalt = privateKeySalt;

    await user.save();

    res.json({
      message: 'User RSA-OAEP sharing key pair saved successfully.',
      publicKey: user.publicKey,
      hasEncryptedPrivateKey: Boolean(user.encryptedPrivateKey)
    });
  } catch (err) {
    console.error('Update keys error:', err);
    res.status(500).json({ error: 'Failed to update user keys.' });
  }
});

/**
 * PUT /api/users/password
 * Protected route to change the user master password.
 * - Authenticates old password with bcrypt
 * - Updates passwordHash with new password
 * - Updates re-wrapped encrypted private key
 * - Updates re-wrapped DEKs in MongoDB for each user file
 *
 * NOTE: Thanks to envelope encryption, file ciphertexts in AWS S3 are 100% untouched!
 */
router.put('/password', authenticateToken, async (req, res) => {
  try {
    const {
      oldPassword,
      newPassword,
      rewrappedPrivateKey,
      privateKeyIv,
      privateKeySalt,
      rewrappedFiles
    } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Both oldPassword and newPassword are required.' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    // Verify current password against stored bcrypt hash
    const isOldPasswordValid = await user.comparePassword(oldPassword);
    if (!isOldPasswordValid) {
      return res.status(401).json({ error: 'Current password incorrect. Re-wrapping aborted.' });
    }

    // Update password hash
    user.passwordHash = await User.hashPassword(newPassword);

    // Update re-wrapped private key
    if (rewrappedPrivateKey) {
      user.encryptedPrivateKey = rewrappedPrivateKey;
      if (privateKeyIv) user.privateKeyIv = privateKeyIv;
      if (privateKeySalt) user.privateKeySalt = privateKeySalt;
    }

    await user.save();

    // Batch update re-wrapped file DEKs in MongoDB
    let filesUpdatedCount = 0;
    if (Array.isArray(rewrappedFiles) && rewrappedFiles.length > 0) {
      for (const item of rewrappedFiles) {
        const updateData = { wrappedDEK: item.wrappedDEK };
        if (item.dekIv) updateData.dekIv = item.dekIv;
        if (item.salt) updateData.salt = item.salt;

        const res = await File.updateOne(
          { _id: item.fileId, ownerId: user._id },
          { $set: updateData }
        );
        if (res.modifiedCount > 0) {
          filesUpdatedCount++;
        }
      }
    }

    res.json({
      message: 'Password updated successfully. Master KEK re-derived and all keys re-wrapped.',
      filesUpdated: filesUpdatedCount,
      tradeoffSummary: {
        ciphertextReEncryptedBytes: 0,
        ciphertextsUntouched: true,
        dekRewrappedCount: filesUpdatedCount,
        note: 'Envelope encryption benefit: Only small 32-byte DEKs were re-wrapped. S3 file objects were untouched.'
      }
    });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: `Failed to update password: ${err.message}` });
  }
});

module.exports = router;
