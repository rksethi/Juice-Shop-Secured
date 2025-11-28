/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      
      // SECURITY FIX: SSRF mitigation - validate URL and restrict to HTTP/HTTPS only
      let parsedUrl: URL
      try {
        parsedUrl = new URL(url)
      } catch (error) {
        logger.warn(`Invalid URL provided for profile image: ${url}`)
        res.status(400).json({ error: 'Invalid URL format' })
        return
      }
      
      // Only allow HTTP and HTTPS protocols
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        logger.warn(`Blocked non-HTTP(S) URL for profile image: ${url}`)
        res.status(400).json({ error: 'Only HTTP and HTTPS URLs are allowed' })
        return
      }
      
      // SECURITY FIX: Whitelist allowed domains/hosts to prevent SSRF
      const allowedHosts = [
        'i.imgur.com',
        'imgur.com',
        'images.unsplash.com',
        'unsplash.com',
        'via.placeholder.com',
        'picsum.photos'
      ]
      
      if (!allowedHosts.includes(parsedUrl.hostname)) {
        logger.warn(`Blocked SSRF attempt to ${parsedUrl.hostname} from ${req.ip}`)
        res.status(403).json({ error: 'URL host not allowed. Please use an image hosting service.' })
        return
      }
      
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url, {
            // SECURITY FIX: Set timeout and redirect limits to prevent SSRF
            signal: AbortSignal.timeout(5000), // 5 second timeout
            redirect: 'follow',
            // Limit redirects
            headers: {
              'User-Agent': 'JuiceShop/1.0'
            }
          })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
