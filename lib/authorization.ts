/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from './insecurity'
import logger from './logger'

/**
 * SECURITY FIX: Authorization middleware to prevent IDOR (Insecure Direct Object Reference) vulnerabilities
 * Ensures users can only access their own resources
 */
export function authorizeResourceAccess (resourceUserIdExtractor: (req: Request) => number | string | null) {
  return (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    
    if (!loggedInUser) {
      logger.warn(`Unauthorized access attempt to ${req.path} from ${req.ip}`)
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    
    const requestedResourceUserId = resourceUserIdExtractor(req)
    const loggedInUserId = loggedInUser.data.id
    
    // Allow access if user is admin
    if (loggedInUser.data.role === 'admin') {
      next()
      return
    }
    
    // Check if user is accessing their own resource
    if (requestedResourceUserId && String(requestedResourceUserId) !== String(loggedInUserId)) {
      logger.warn(`IDOR attempt blocked: User ${loggedInUserId} attempted to access resource owned by ${requestedResourceUserId} at ${req.path}`)
      res.status(403).json({ error: 'Access denied: You can only access your own resources' })
      return
    }
    
    next()
  }
}

/**
 * SECURITY FIX: Middleware to verify user owns the resource by ID parameter
 */
export function verifyResourceOwnership (paramName: string = 'id') {
  return authorizeResourceAccess((req) => {
    // Try to get user ID from route parameter
    const id = req.params[paramName]
    if (!id) return null
    
    // For user resources, the ID should match the user ID
    // This is a simplified check - specific routes should implement more detailed checks
    return id
  })
}

