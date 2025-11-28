/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import logger from './logger'
import { sequelize } from '../models'

/**
 * SECURITY FIX: Database activity logging
 * Logs all database operations for audit and security monitoring
 */
export class DatabaseLogger {
  /**
   * Log database query execution
   */
  static logQuery (query: string, replacements?: any, userId?: number) {
    logger.info('Database Query', {
      query: query.substring(0, 200), // Truncate long queries
      replacements: replacements ? Object.keys(replacements).length + ' parameters' : 'none',
      userId: userId || 'anonymous',
      timestamp: new Date().toISOString()
    })
  }

  /**
   * Log database transaction events
   */
  static logTransaction (event: 'start' | 'commit' | 'rollback', transactionId?: string) {
    logger.info('Database Transaction', {
      event,
      transactionId: transactionId || 'unknown',
      timestamp: new Date().toISOString()
    })
  }

  /**
   * Log database configuration changes
   */
  static logConfigChange (change: string, userId?: number) {
    logger.warn('Database Configuration Change', {
      change,
      userId: userId || 'system',
      timestamp: new Date().toISOString()
    })
  }

  /**
   * Log data modifications
   */
  static logDataModification (operation: 'INSERT' | 'UPDATE' | 'DELETE', table: string, recordId?: number, userId?: number) {
    logger.info('Database Data Modification', {
      operation,
      table,
      recordId: recordId || 'unknown',
      userId: userId || 'anonymous',
      timestamp: new Date().toISOString()
    })
  }

  /**
   * Log database errors
   */
  static logError (error: Error, query?: string) {
    logger.error('Database Error', {
      error: error.message,
      query: query ? query.substring(0, 200) : 'unknown',
      stack: error.stack,
      timestamp: new Date().toISOString()
    })
  }
}

/**
 * SECURITY FIX: Hook into Sequelize to log all database operations
 */
export function setupDatabaseLogging () {
  sequelize.addHook('beforeQuery', (options: any) => {
    if (options.type === 'SELECT') {
      // Log SELECT queries (but not all to avoid log spam)
      if (options.sql && options.sql.includes('Users') || options.sql.includes('Cards')) {
        DatabaseLogger.logQuery(options.sql, options.replacements)
      }
    }
  })

  sequelize.addHook('afterQuery', (options: any, query: any) => {
    // Log errors
    if (query && query.error) {
      DatabaseLogger.logError(query.error, options.sql)
    }
  })

  // Log transaction events
  sequelize.addHook('beforeTransactionCommit', (transaction: any) => {
    DatabaseLogger.logTransaction('commit', transaction.id)
  })

  sequelize.addHook('beforeTransactionRollback', (transaction: any) => {
    DatabaseLogger.logTransaction('rollback', transaction.id)
  })
}

