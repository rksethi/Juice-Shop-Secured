/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import logger from './logger'

/**
 * SECURITY FIX: Token utilities for secure token handling
 * Implements T281, T284, and T1919 countermeasures
 */

// Store revoked tokens (in production, use Redis or database)
const revokedTokens: Set<string> = new Set()

/**
 * Mask a token for logging/display purposes
 * Shows only first 4 and last 4 characters, masks the rest
 * T281: Do not include access token values in logs
 */
export function maskToken (token: string | undefined | null): string {
  if (!token || token.length < 8) {
    return '***'
  }
  const start = token.substring(0, 4)
  const end = token.substring(token.length - 4)
  return `${start}${'*'.repeat(Math.max(0, token.length - 8))}${end}`
}

/**
 * Hash a token for logging purposes
 * T281: Hash or encrypt token values in logs
 */
export function hashTokenForLogging (token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex').substring(0, 16)
}

/**
 * Revoke a token
 * T284: Implement a way to revoke access tokens
 */
export function revokeToken (token: string): void {
  revokedTokens.add(token)
  logger.info('Token revoked', { tokenHash: hashTokenForLogging(token) })
}

/**
 * Check if a token is revoked
 * T284: Implement a way to revoke access tokens
 */
export function isTokenRevoked (token: string): boolean {
  return revokedTokens.has(token)
}

/**
 * Generate a secure random token
 * T284: Generate an access token that is long enough (minimum 128 bit = 32 hex chars)
 * Uses cryptographically secure random number generator
 */
export function generateSecureToken (length: number = 32): string {
  // Generate 32 bytes (256 bits) of random data, convert to hex (64 chars)
  // This exceeds the minimum 128-bit requirement (32 hex chars)
  return crypto.randomBytes(length).toString('hex')
}

/**
 * Log token access activity without exposing the token
 * T281: Log all access and activity using access tokens, but don't include token values
 */
export function logTokenAccess (userId: number, action: string, tokenHash?: string): void {
  logger.info('Token access activity', {
    userId,
    action,
    tokenHash: tokenHash || 'N/A',
    timestamp: new Date().toISOString()
  })
}

