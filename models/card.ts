/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'
import * as panEncryption from '../lib/panEncryption'

class Card extends Model<
InferAttributes<Card>,
InferCreationAttributes<Card>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare fullName: string
  declare cardNum: number | string // Can be number (legacy) or encrypted string
  declare encryptedCardNum?: string // SECURITY FIX: Encrypted PAN storage
  declare expMonth: number
  declare expYear: number
}

const CardModelInit = (sequelize: Sequelize) => {
  Card.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      fullName: DataTypes.STRING,
      cardNum: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true,
          min: 1000000000000000,
          max: 9999999999999998
        },
        // SECURITY FIX: Encrypt PAN before storing
        set (value: number | string) {
          if (typeof value === 'string' && value.includes(':')) {
            // Already encrypted, store as-is
            this.setDataValue('encryptedCardNum', value)
            // Keep last 4 digits for display purposes (masked)
            this.setDataValue('cardNum', 0)
          } else {
            // New PAN - encrypt it
            const panString = String(value)
            if (/^\d{13,19}$/.test(panString)) {
              const encrypted = panEncryption.encryptPAN(panString)
              this.setDataValue('encryptedCardNum', encrypted)
              // Store last 4 digits for display (not full number)
              this.setDataValue('cardNum', parseInt(panString.substring(panString.length - 4)))
            } else {
              this.setDataValue('cardNum', value)
            }
          }
        },
        get () {
          // Return masked PAN for display (never return full PAN)
          const encrypted = this.getDataValue('encryptedCardNum')
          if (encrypted) {
            try {
              const decrypted = panEncryption.decryptPAN(encrypted)
              return panEncryption.maskPAN(decrypted)
            } catch {
              return '****'
            }
          }
          return this.getDataValue('cardNum')
        }
      },
      encryptedCardNum: {
        type: DataTypes.STRING,
        allowNull: true
      },
      expMonth: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true,
          min: 1,
          max: 12
        }
      },
      expYear: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true,
          min: 2080,
          max: 2099
        }
      }
    },
    {
      tableName: 'Cards',
      sequelize
    }
  )
}

export { Card as CardModel, CardModelInit }
