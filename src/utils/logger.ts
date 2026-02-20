/**
 * Structured logger using Winston.
 * Outputs JSON in production, pretty-printed in development.
 */
import winston from 'winston';
import { config } from '../config';

const { combine, timestamp, json, errors, colorize, simple } = winston.format;

const devFormat = combine(
  colorize(),
  timestamp({ format: 'HH:mm:ss' }),
  errors({ stack: true }),
  simple()
);

const prodFormat = combine(
  timestamp(),
  errors({ stack: true }),
  json()
);

export const logger = winston.createLogger({
  level: config.NODE_ENV === 'production' ? 'info' : 'debug',
  format: config.NODE_ENV === 'production' ? prodFormat : devFormat,
  transports: [
    new winston.transports.Console(),
  ],
  exitOnError: false,
});

// Create child loggers for each subsystem
export const oidcLogger = logger.child({ subsystem: 'oidc' });
export const samlLogger = logger.child({ subsystem: 'saml' });
export const scimLogger = logger.child({ subsystem: 'scim' });
export const webauthnLogger = logger.child({ subsystem: 'webauthn' });
export const sessionLogger = logger.child({ subsystem: 'session' });
export const auditLogger = logger.child({ subsystem: 'audit' });
export const certLogger = logger.child({ subsystem: 'certificate' });
