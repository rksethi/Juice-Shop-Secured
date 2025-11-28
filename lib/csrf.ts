/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import crypto from 'node:crypto'
import logger from './logger'

/**
 * SECURITY FIX: CSRF protection middleware
 * Implements Double Submit Cookie pattern for CSRF protection
 * Since frontend and backend are on the same origin, this is the recommended approach
 */

// Store CSRF tokens in memory (in production, use Redis or similar)
const csrfTokens = new Map<string, { token: string, expires: number }>()

// Clean up expired tokens every 5 minutes
setInterval(() => {
  const now = Date.now()
  for (const [key, value] of csrfTokens.entries()) {
    if (value.expires < now) {
      csrfTokens.delete(key)
    }
  }
}, 5 * 60 * 1000)

/**
 * Generate a CSRF token for a session
 */
export function generateCsrfToken (sessionId: string): string {
  const token = crypto.randomBytes(32).toString('hex')
  const expires = Date.now() + (60 * 60 * 1000) // 1 hour expiration
  
  csrfTokens.set(sessionId, { token, expires })
  return token
}

/**
 * Verify CSRF token from request
 */
export function verifyCsrfToken (sessionId: string, token: string): boolean {
  const stored = csrfTokens.get(sessionId)
  if (!stored) {
    return false
  }
  
  if (stored.expires < Date.now()) {
    csrfTokens.delete(sessionId)
    return false
  }
  
  return crypto.timingSafeEqual(
    Buffer.from(stored.token),
    Buffer.from(token)
  )
}

/**
 * CSRF protection middleware
 * Skips GET, HEAD, OPTIONS requests as per CSRF best practices
 */
export function csrfProtection () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip CSRF protection for safe HTTP methods
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next()
    }
    
    // Get session ID from cookie or create one
    const sessionId = req.cookies.sessionId || crypto.randomBytes(16).toString('hex')
    if (!req.cookies.sessionId) {
      res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      })
    }
    
    // Get CSRF token from header or body
    const csrfToken = req.headers['x-csrf-token'] || req.body?._csrf
    
    if (!csrfToken) {
      logger.warn(`CSRF token missing for ${req.method} ${req.path} from ${req.ip}`)
      res.status(403).json({ error: 'CSRF token missing' })
      return
    }
    
    if (!verifyCsrfToken(sessionId, csrfToken)) {
      logger.warn(`CSRF token validation failed for ${req.method} ${req.path} from ${req.ip}`)
      res.status(403).json({ error: 'CSRF token validation failed' })
      return
    }
    
    next()
  }
}

/**
 * Middleware to add CSRF token to response
 * Call this on GET requests to provide token to frontend
 */
export function addCsrfToken () {
  return (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies.sessionId || crypto.randomBytes(16).toString('hex')
    if (!req.cookies.sessionId) {
      res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      })
    }
    
    const token = generateCsrfToken(sessionId)
    res.locals.csrfToken = token
    res.setHeader('X-CSRF-Token', token)
    next()
  }
}

