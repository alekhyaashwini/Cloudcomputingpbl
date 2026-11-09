const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * JWT Authentication Middleware
 * Validates the Authorization Bearer token on protected API routes.
 * Decodes the JWT, verifies expiration, and attaches the authenticated user record to req.user.
 */
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication failed: Missing or malformed Authorization Bearer token.'
      });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Authentication failed: No token provided.' });
    }

    // Verify token with configured JWT secret
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'super_secret_jwt_key_change_in_production_pbl_2026'
    );

    // Fetch user without passwordHash to ensure password data is never held in request scope
    const user = await User.findById(decoded.userId || decoded.id).select('-passwordHash');
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed: User account no longer exists or has been deactivated.'
      });
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired: Please log in again.' });
    }
    return res.status(401).json({
      error: 'Authentication failed: Invalid token signature or corrupted credentials.'
    });
  }
};

module.exports = authMiddleware;
