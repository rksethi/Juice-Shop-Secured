/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CardModel } from '../models/card'

interface displayCard {
  UserId: number
  id: number
  fullName: string
  cardNum: string
  expMonth: number
  expYear: number
}

export function getPaymentMethods () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const displayableCards: displayCard[] = []
    const cards = await CardModel.findAll({ where: { UserId: req.body.UserId } })
    cards.forEach(card => {
      const displayableCard: displayCard = {
        UserId: card.UserId,
        id: card.id,
        fullName: card.fullName,
        cardNum: '',
        expMonth: card.expMonth,
        expYear: card.expYear
      }
      // SECURITY FIX: cardNum getter already returns masked PAN (first 6 + last 4 digits)
      displayableCard.cardNum = String(card.cardNum)
      displayableCards.push(displayableCard)
    })
    res.status(200).json({ status: 'success', data: displayableCards })
  }
}

export function getPaymentMethodById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const card = await CardModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    const displayableCard: displayCard = {
      UserId: 0,
      id: 0,
      fullName: '',
      cardNum: '',
      expMonth: 0,
      expYear: 0
    }
    if (card != null) {
      displayableCard.UserId = card.UserId
      displayableCard.id = card.id
      displayableCard.fullName = card.fullName
      displayableCard.expMonth = card.expMonth
      displayableCard.expYear = card.expYear

      // SECURITY FIX: cardNum getter already returns masked PAN (first 6 + last 4 digits)
      displayableCard.cardNum = String(card.cardNum)
    }
    if ((card != null) && displayableCard) {
      res.status(200).json({ status: 'success', data: displayableCard })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected' })
    }
  }
}

export function delPaymentMethodById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const card = await CardModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (card) {
      res.status(200).json({ status: 'success', data: 'Card deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
