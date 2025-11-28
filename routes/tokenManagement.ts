/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import * as tokenUtils from '../lib/tokenUtils'
import logger from '../lib/logger'

/**
 * SECURITY FIX: Token management routes
 * T281: Follow best practices when handling access tokens
 * T284: Generate secure access tokens and allow revocation/regeneration
 */

/**
 * Revoke current user's token
 * T284: Implement a way to revoke access tokens
 */
export function revokeToken () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '')
    const user = security.authenticatedUsers.from(req)

    if (!token || !user) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }

    // T284: Revoke the token
    tokenUtils.revokeToken(token)
    
    // Remove from authenticated users map
    security.authenticatedUsers.tokenMap[token] = undefined
    if (user.data.id) {
      delete security.authenticatedUsers.idMap[user.data.id]
    }

    // T281: Log token revocation without exposing token value
    tokenUtils.logTokenAccess(user.data.id, 'token_revoked', tokenUtils.hashTokenForLogging(token))

    res.json({ 
      status: 'success', 
      message: 'Token revoked successfully',
      // T281: Display masked token for user confirmation
      tokenDisplay: tokenUtils.maskToken(token)
    })
  }
}

/**
 * Regenerate token for current user
 * T284: Allow users to regenerate the token
 */
export function regenerateToken () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const oldToken = req.cookies.token || req.headers.authorization?.replace('Bearer ', '')
    const user = security.authenticatedUsers.from(req)

    if (!user) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }

    try {
      // T284: Revoke old token
      if (oldToken) {
        tokenUtils.revokeToken(oldToken)
        security.authenticatedUsers.tokenMap[oldToken] = undefined
      }

      // T284: Generate new secure token
      const newToken = security.authorize(user)
      security.authenticatedUsers.put(newToken, user)

      // T281: Log token regeneration without exposing token values
      tokenUtils.logTokenAccess(user.data.id, 'token_regenerated', tokenUtils.hashTokenForLogging(newToken))

      // T281: Return masked token for display (user should copy full token only once)
      res.json({ 
        status: 'success',
        message: 'Token regenerated successfully',
        token: newToken, // Full token returned once for user to copy
        tokenDisplay: tokenUtils.maskToken(newToken), // Masked version for display
        warning: 'Please save this token securely. It will not be shown again.'
      })

      // T284: In production, send email notification about new token
      // For now, we log it
      logger.info('Token regenerated for user', { 
        userId: user.data.id, 
        email: user.data.email,
        tokenHash: tokenUtils.hashTokenForLogging(newToken)
      })
    } catch (error: any) {
      logger.error('Error regenerating token', { error: error.message, userId: user.data.id })
      next(error)
    }
  }
}

/**
 * Get current token information (masked)
 * T281: Display messages to educate users about displaying access tokens
 */
export function getTokenInfo () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '')
    const user = security.authenticatedUsers.from(req)

    if (!token || !user) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }

    // T281: Return masked token and security information
    res.json({
      status: 'success',
      tokenDisplay: tokenUtils.maskToken(token),
      tokenHash: tokenUtils.hashTokenForLogging(token),
      securityInfo: {
        message: 'Keep your access token secure. Never share it publicly or include it in URLs.',
        bestPractices: [
          'Store tokens securely and never commit them to version control',
          'Do not include tokens in query parameters',
          'Use tokens only in Authorization headers or request bodies',
          'Revoke tokens immediately if they are compromised',
          'Regenerate tokens periodically for enhanced security'
        ]
      }
    })
  }
}

