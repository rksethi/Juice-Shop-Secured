/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

/**
 * SECURITY FIX: Logout route that sends Clear-Site-Data header
 * This clears browser storage (cookies, localStorage, sessionStorage, cache) on logout
 */
export function logout () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '')
    
    // Remove user from authenticated users map
    if (token && security.authenticatedUsers.get(token)) {
      security.authenticatedUsers.tokenMap[token] = undefined
      const userId = security.authenticatedUsers.get(token)?.data?.id
      if (userId) {
        delete security.authenticatedUsers.idMap[userId]
      }
    }
    
    // SECURITY FIX: Send Clear-Site-Data header to clear browser storage
    res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"')
    
    // Clear the token cookie
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    })
    
    res.json({ status: 'success', message: 'Logged out successfully' })
  }
}

