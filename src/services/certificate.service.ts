/**
 * Certificate management service.
 * Handles certificate parsing, expiry checks, rotation alerts, and validation.
 */
import { query } from '../config/database';
import { parseCertExpiry, certFingerprint } from '../utils/crypto';
import { certLogger } from '../utils/logger';
import { auditService, AuditEventType } from './audit.service';
import { config } from '../config';

export interface CertInfo {
  pem: string;
  fingerprint: string;
  expiresAt: Date | null;
  daysUntilExpiry: number | null;
  isExpired: boolean;
  isExpiringSoon: boolean;
}

class CertificateService {
  /**
   * Parses a PEM certificate and returns metadata.
   */
  parseCert(pem: string): CertInfo {
    const expiresAt = parseCertExpiry(pem);
    const now = Date.now();
    const daysUntilExpiry = expiresAt
      ? Math.floor((expiresAt.getTime() - now) / (1000 * 60 * 60 * 24))
      : null;

    return {
      pem,
      fingerprint: certFingerprint(pem),
      expiresAt,
      daysUntilExpiry,
      isExpired: daysUntilExpiry !== null && daysUntilExpiry < 0,
      isExpiringSoon:
        daysUntilExpiry !== null &&
        daysUntilExpiry >= 0 &&
        daysUntilExpiry <= config.CERT_EXPIRY_WARN_DAYS,
    };
  }

  /**
   * Validates and stores a new IdP or SP certificate in an IdP config.
   * Rejects expired certificates.
   */
  async updateIdpCertificate(
    tenantId: string,
    idpConfigId: string,
    pemCert: string
  ): Promise<CertInfo> {
    const info = this.parseCert(pemCert);

    if (info.isExpired) {
      throw new Error(
        `Certificate is already expired (expired ${info.expiresAt?.toISOString()})`
      );
    }

    await query(
      `UPDATE idp_configs
         SET saml_idp_certificate = $1,
             idp_cert_expires_at = $2,
             updated_at = NOW()
       WHERE id = $3 AND tenant_id = $4`,
      [pemCert, info.expiresAt, idpConfigId, tenantId]
    );

    if (info.isExpiringSoon) {
      certLogger.warn('IdP certificate expires soon', {
        tenantId,
        idpConfigId,
        daysUntilExpiry: info.daysUntilExpiry,
        fingerprint: info.fingerprint,
      });
      await auditService.log({
        tenantId,
        idpConfigId,
        eventType: AuditEventType.CERT_EXPIRY_WARNING,
        outcome: 'success',
        details: {
          certificateType: 'idp',
          daysUntilExpiry: info.daysUntilExpiry,
          fingerprint: info.fingerprint,
        },
      });
    }

    return info;
  }

  /**
   * Scans all IdP configs for certificates expiring within CERT_EXPIRY_WARN_DAYS.
   * Called by a scheduled job.
   */
  async checkExpiringCertificates(): Promise<void> {
    const warnDate = new Date(
      Date.now() + config.CERT_EXPIRY_WARN_DAYS * 24 * 60 * 60 * 1000
    );

    const result = await query<{
      id: string;
      tenant_id: string;
      name: string;
      idp_cert_expires_at: Date | null;
      sp_cert_expires_at: Date | null;
    }>(
      `SELECT id, tenant_id, name, idp_cert_expires_at, sp_cert_expires_at
         FROM idp_configs
        WHERE is_active = true
          AND (
            idp_cert_expires_at <= $1
            OR sp_cert_expires_at <= $1
          )`,
      [warnDate]
    );

    for (const row of result.rows) {
      const types: string[] = [];
      if (row.idp_cert_expires_at && row.idp_cert_expires_at <= warnDate) {
        types.push('idp');
      }
      if (row.sp_cert_expires_at && row.sp_cert_expires_at <= warnDate) {
        types.push('sp');
      }

      certLogger.warn('Certificate expiring soon', {
        tenantId: row.tenant_id,
        idpConfigId: row.id,
        name: row.name,
        types,
        idpCertExpiry: row.idp_cert_expires_at,
        spCertExpiry: row.sp_cert_expires_at,
      });

      await auditService.log({
        tenantId: row.tenant_id,
        idpConfigId: row.id,
        eventType: AuditEventType.CERT_EXPIRY_WARNING,
        outcome: 'success',
        details: {
          configName: row.name,
          certificateTypes: types,
          idpCertExpiry: row.idp_cert_expires_at,
          spCertExpiry: row.sp_cert_expires_at,
        },
      });
    }
  }

  /**
   * Validates that a PEM certificate's signature algorithm is SHA-256 or stronger.
   * Returns true if acceptable.
   */
  validateSignatureAlgorithm(pemCert: string): boolean {
    try {
      const forge = require('node-forge') as typeof import('node-forge');
      const cert = forge.pki.certificateFromPem(pemCert);
      const sigAlg = cert.signatureOid;
      // OIDs for SHA-256 and SHA-384 and SHA-512 based signature algorithms
      const acceptableOids = [
        '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
        '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
        '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
        '1.2.840.10045.4.3.2',   // ecdsa-with-SHA256
        '1.2.840.10045.4.3.3',   // ecdsa-with-SHA384
        '1.2.840.10045.4.3.4',   // ecdsa-with-SHA512
      ];
      return acceptableOids.includes(sigAlg);
    } catch {
      return false;
    }
  }
}

export const certificateService = new CertificateService();
