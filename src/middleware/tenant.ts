/**
 * Tenant isolation middleware.
 * Resolves tenant ID from request and attaches it to req.tenantId.
 * Enforces strict multi-tenant data isolation.
 */
import { Request, Response, NextFunction } from 'express';
import { tenantService } from '../services/tenant.service';

declare global {
  namespace Express {
    interface Request {
      tenantId?: string;
    }
  }
}

/**
 * Resolves tenant from:
 * 1. URL path parameter (:tenantId)
 * 2. X-Tenant-ID header (for programmatic access)
 * 3. Subdomain (e.g. acme.sso.legora.com → acme)
 * 4. Host-based domain lookup
 */
export async function resolveTenant(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // 1. Explicit path param (highest priority – used by SSO callback routes)
    const paramTenantId =
      req.params['tenantId'] ??
      req.params['tenant_id'];
    if (paramTenantId) {
      req.tenantId = paramTenantId;
      next();
      return;
    }

    // 2. Explicit header
    const headerTenantId = req.headers['x-tenant-id'] as string | undefined;
    if (headerTenantId) {
      req.tenantId = headerTenantId;
      next();
      return;
    }

    // 3. Domain-based lookup
    const host = req.hostname;
    if (host) {
      const tenant = await tenantService.getTenantByDomain(host);
      if (tenant) {
        req.tenantId = tenant['id'] as string;
        next();
        return;
      }

      // Subdomain extraction (e.g. acme.sso.legora.com)
      const parts = host.split('.');
      if (parts.length > 2) {
        const subdomain = parts[0];
        const subTenant = await tenantService.getTenantByDomain(subdomain);
        if (subTenant) {
          req.tenantId = subTenant['id'] as string;
          next();
          return;
        }
      }
    }

    // No tenant found – this is only an error for tenant-scoped endpoints
    next();
  } catch {
    res.status(500).json({ error: 'Failed to resolve tenant' });
  }
}

/**
 * Middleware that enforces tenant is resolved (for tenant-scoped routes).
 */
export function requireTenant(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.tenantId) {
    res.status(400).json({ error: 'Tenant could not be determined from request' });
    return;
  }
  next();
}
