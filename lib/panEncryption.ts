/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'

/**
 * SECURITY FIX: PAN (Primary Account Number) encryption utilities
 * Implements PCI-DSS compliant encryption for credit card numbers
 */

const ALGORITHM = 'aes-256-gcm'
const KEY_LENGTH = 32 // 256 bits
const IV_LENGTH = 16 // 128 bits
const TAG_LENGTH = 16 // 128 bits

// In production, this should come from environment variable or key management system
const getEncryptionKey = (): Buffer => {
  const key = process.env.PAN_ENCRYPTION_KEY || crypto.randomBytes(KEY_LENGTH).toString('hex')
  // If key is hex string, convert to buffer; otherwise use directly
  if (typeof key === 'string' && key.length === KEY_LENGTH * 2) {
    return Buffer.from(key, 'hex')
  }
  // Generate a deterministic key from environment (for development)
  return crypto.scryptSync(key, 'salt', KEY_LENGTH)
}

/**
 * Encrypt a PAN (Primary Account Number)
 * Returns encrypted data in format: iv:tag:encryptedData (all base64 encoded)
 */
export function encryptPAN (pan: string | number): string {
  const panString = String(pan)
  
  // Validate PAN format (basic check)
  if (!/^\d{13,19}$/.test(panString)) {
    throw new Error('Invalid PAN format')
  }
  
  const key = getEncryptionKey()
  const iv = crypto.randomBytes(IV_LENGTH)
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv)
  
  let encrypted = cipher.update(panString, 'utf8', 'base64')
  encrypted += cipher.final('base64')
  
  const tag = cipher.getAuthTag()
  
  // Return format: iv:tag:encryptedData (all base64)
  return `${iv.toString('base64')}:${tag.toString('base64')}:${encrypted}`
}

/**
 * Decrypt a PAN (Primary Account Number)
 * Accepts encrypted data in format: iv:tag:encryptedData (all base64 encoded)
 */
export function decryptPAN (encryptedPAN: string): string {
  const parts = encryptedPAN.split(':')
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted PAN format')
  }
  
  const [ivBase64, tagBase64, encryptedBase64] = parts
  
  const key = getEncryptionKey()
  const iv = Buffer.from(ivBase64, 'base64')
  const tag = Buffer.from(tagBase64, 'base64')
  const encrypted = Buffer.from(encryptedBase64, 'base64')
  
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
  decipher.setAuthTag(tag)
  
  let decrypted = decipher.update(encrypted, undefined, 'utf8')
  decrypted += decipher.final('utf8')
  
  return decrypted
}

/**
 * Mask PAN for display (shows only first 6 and last 4 digits)
 * PCI-DSS compliant masking
 */
export function maskPAN (pan: string | number): string {
  const panString = String(pan)
  if (panString.length < 10) {
    return '*'.repeat(panString.length)
  }
  
  // Show first 6 digits (BIN) and last 4 digits
  const first6 = panString.substring(0, 6)
  const last4 = panString.substring(panString.length - 4)
  const masked = '*'.repeat(Math.max(0, panString.length - 10))
  
  return `${first6}${masked}${last4}`
}

/**
 * Hash PAN for storage (one-way hash, cannot be decrypted)
 * Use this when you don't need to retrieve the original PAN
 */
export function hashPAN (pan: string | number): string {
  const panString = String(pan)
  // Use SHA-256 with salt for one-way hashing
  const salt = process.env.PAN_HASH_SALT || 'default-salt-change-in-production'
  return crypto.createHash('sha256').update(panString + salt).digest('hex')
}

