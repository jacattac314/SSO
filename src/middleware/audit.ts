/**
 * HTTP request audit middleware.
 * Logs each incoming request with tenant, IP, and method context.
 */
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export function requestLogger(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const start = Date.now();
  const { method, originalUrl } = req;
  const ip = req.ip ?? req.socket.remoteAddress;

  res.on('finish', () => {
    const duration = Date.now() - start;
    const tenantId = req.tenantId;
    logger.info('http_request', {
      method,
      url: originalUrl,
      status: res.statusCode,
      duration_ms: duration,
      ip,
      tenant_id: tenantId,
      user_agent: req.headers['user-agent'],
    });
  });

  next();
}
