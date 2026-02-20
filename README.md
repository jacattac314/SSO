# Legora SSO Integration – MVP

Enterprise-grade Single Sign-On for Legora's collaborative legal AI platform.

## Supported Protocols

| Protocol | Flow |
|----------|------|
| **OIDC** (Authorization Code + PKCE) | SP-initiated, RP-initiated logout |
| **SAML 2.0** | SP-initiated, IdP-initiated, Single Logout (SLO) |
| **WebAuthn / FIDO2** | Phishing-resistant MFA (platform + roaming authenticators) |
| **SCIM 2.0** | Automated user/group lifecycle management |

## Architecture

```
                       ┌─────────────────────────────────────┐
                       │           Legora SSO Server          │
                       │                                      │
  ┌───────┐  OIDC/SAML │  ┌──────────┐   ┌───────────────┐  │
  │  IdP  │◄──────────►│  │Auth Engine│   │ SCIM 2.0 API  │  │
  │(Okta/ │            │  │(OIDC+SAML)│   │(User Lifecycle)│  │
  │Azure) │            │  └──────────┘   └───────────────┘  │
  └───────┘            │       │                 │           │
                       │  ┌────▼────────────────▼────────┐  │
                       │  │        PostgreSQL (multi-tenant)│  │
                       │  └─────────────────────────────┘  │
                       │       │         │         │        │
                       │  Sessions  Audit Logs  Users/Certs │
                       └─────────────────────────────────────┘
                              │               │
                    ┌─────────▼───┐  ┌────────▼──────┐
                    │  DMS Layer  │  │ Word Add-in   │
                    │(ND/iManage/ │  │ (Office SSO)  │
                    │ SharePoint) │  └───────────────┘
                    └─────────────┘
```

## Quick Start

### Prerequisites
- Node.js 20+
- PostgreSQL 14+
- Redis 7+ (session store)

### Setup

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run database migrations
npm run db:migrate

# Start development server
npm run dev

# Run tests
npm test
```

## API Endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oidc/:tenantId/login` | OIDC SP-initiated login |
| `GET` | `/auth/oidc/:tenantId/callback` | OIDC authorization code callback |
| `GET` | `/auth/oidc/:tenantId/logout` | OIDC RP-initiated logout |
| `GET` | `/auth/saml/:tenantId/login` | SAML SP-initiated login |
| `POST` | `/auth/saml/:tenantId/acs` | SAML Assertion Consumer Service |
| `GET` | `/auth/saml/:tenantId/metadata` | SAML SP metadata XML |
| `GET` | `/auth/saml/:tenantId/logout` | SAML SP-initiated SLO |
| `POST/GET` | `/auth/saml/:tenantId/slo` | SAML IdP-initiated SLO |

### WebAuthn / FIDO2

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/webauthn/register/options` | Get registration challenge |
| `POST` | `/auth/webauthn/register/verify` | Verify & store credential |
| `POST` | `/auth/webauthn/authenticate/options` | Get auth challenge |
| `POST` | `/auth/webauthn/authenticate/verify` | Verify authentication |
| `GET` | `/auth/webauthn/credentials` | List credentials |
| `DELETE` | `/auth/webauthn/credentials/:id` | Remove credential |

### SCIM 2.0

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/scim/v2/Users` | List users (filter, pagination) |
| `POST` | `/scim/v2/Users` | Create user |
| `GET` | `/scim/v2/Users/:id` | Get user |
| `PUT` | `/scim/v2/Users/:id` | Replace user |
| `PATCH` | `/scim/v2/Users/:id` | Partial update (incl. deactivation) |
| `DELETE` | `/scim/v2/Users/:id` | Delete user |
| `GET/POST/PUT/PATCH/DELETE` | `/scim/v2/Groups/*` | Group management |
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM capabilities |

### Admin API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/tenants` | Create tenant |
| `GET` | `/admin/tenants/:id` | Get tenant |
| `POST` | `/admin/tenants/:id/idp-configs` | Add IdP config (OIDC or SAML) |
| `GET` | `/admin/tenants/:id/idp-configs` | List IdP configs |
| `DELETE` | `/admin/tenants/:id/idp-configs/:cid` | Remove IdP config |
| `PUT` | `/admin/tenants/:id/idp-configs/:cid/role-mappings` | Set role mappings |
| `POST` | `/admin/tenants/:id/idp-configs/:cid/certificate` | Rotate certificate |
| `GET` | `/admin/tenants/:id/audit-logs` | Query audit logs |
| `POST` | `/admin/tenants/:id/scim-token` | Rotate SCIM bearer token |

## Security Features

- **PKCE** (RFC 7636) for all OIDC Authorization Code flows
- **SHA-256** signature algorithm enforced for SAML; SHA-1 rejected
- **AES-256-GCM** encryption for secrets at rest (client secrets, private keys, DMS tokens)
- **HttpOnly + Secure + SameSite** cookies for session tokens
- **Rotating refresh tokens** with family-level replay detection
- **Idle timeout** (default 15 min) + **absolute timeout** (default 8 hours) per NIST guidelines
- **FIDO2 UV required** (user verification mandatory for WebAuthn)
- **Certificate expiry alerts** 30 days before expiration
- **Multi-tenant isolation**: every DB row carries `tenant_id`; cross-tenant access prevented
- **Audit log retention**: 365 days (partitioned by year for performance)
- **Rate limiting**: auth endpoints 20 req/15min

## Multi-Tenant Architecture

- Every table has a `tenant_id` column
- Tenant resolution via: URL param → `X-Tenant-ID` header → domain lookup → subdomain
- Per-tenant: IdP configs, SCIM tokens, session timeouts, encryption keys
- SAML audience validation prevents cross-tenant assertion replay

## Attribute Mapping

Configure per IdP config via the Admin API:

```json
{
  "attributeMapping": {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "firstName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "lastName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
  }
}
```

## Compliance

- **SOC 2**: Complete audit logging, access controls, encryption at rest and in transit
- **GDPR**: User deprovisioning via SCIM (`active=false` → immediate session termination), minimal PII storage
- **NIST SP 800-63**: Session timeout policies, MFA requirements
- All traffic: TLS ≥ 1.2 (configured at reverse proxy layer)

## Test Matrix

See PRD for full IdP × Protocol × MFA test matrix.

| IdP | Protocol | MFA | Status |
|-----|----------|-----|--------|
| Okta | OIDC | FIDO2 | ✅ |
| Azure AD | OIDC | FIDO2 | ✅ |
| Okta | SAML | FIDO2 | ✅ |
| Ping | SAML | FIDO2 | ✅ |
| Any | OIDC | None | ❌ (policy enforced) |
