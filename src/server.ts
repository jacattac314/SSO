/**
 * Legora SSO Integration Server – entry point.
 */
import { createApp } from './app';
import { config } from './config';
import { logger } from './utils/logger';
import { closePool } from './config/database';
import { certificateService } from './services/certificate.service';
import { sessionService } from './services/session.service';
import { auditService } from './services/audit.service';

const app = createApp();

const server = app.listen(config.PORT, () => {
  logger.info('Legora SSO server started', {
    port: config.PORT,
    env: config.NODE_ENV,
    baseUrl: config.BASE_URL,
  });
});

// ─── Background Jobs ──────────────────────────────────────────────────────────

// Check for expiring certificates every 12 hours
const certCheckInterval = setInterval(
  () => {
    certificateService.checkExpiringCertificates().catch((err) => {
      logger.error('Certificate expiry check failed', { err });
    });
  },
  12 * 60 * 60 * 1000
);

// Purge expired sessions every hour
const sessionPurgeInterval = setInterval(
  () => {
    sessionService.purgeExpired().then((count) => {
      if (count > 0) {
        logger.info('Purged expired sessions', { count });
      }
    }).catch((err) => {
      logger.error('Session purge failed', { err });
    });
  },
  60 * 60 * 1000
);

// Purge old audit logs daily
const auditPurgeInterval = setInterval(
  () => {
    auditService.purgeOldLogs(config.AUDIT_LOG_RETENTION_DAYS).then((count) => {
      if (count > 0) {
        logger.info('Purged old audit logs', { count });
      }
    }).catch((err) => {
      logger.error('Audit log purge failed', { err });
    });
  },
  24 * 60 * 60 * 1000
);

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

function shutdown(signal: string): void {
  logger.info(`Received ${signal}, shutting down gracefully`);

  clearInterval(certCheckInterval);
  clearInterval(sessionPurgeInterval);
  clearInterval(auditPurgeInterval);

  server.close(async () => {
    logger.info('HTTP server closed');
    await closePool();
    logger.info('Database pool closed');
    process.exit(0);
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', { reason });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { err });
  process.exit(1);
});
