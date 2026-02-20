/**
 * Unit tests for XML utilities (SP metadata generation).
 */
import { generateSpMetadata, parseXml } from '../../src/utils/xml';

describe('XML utilities', () => {
  describe('generateSpMetadata', () => {
    it('should generate valid SAML SP metadata XML', () => {
      const metadata = generateSpMetadata({
        entityId: 'https://sso.legora.com/saml/metadata',
        acsUrl: 'https://sso.legora.com/auth/saml/tenant-1/acs',
        sloUrl: 'https://sso.legora.com/auth/saml/tenant-1/slo',
      });

      expect(metadata).toContain('EntityDescriptor');
      expect(metadata).toContain('SPSSODescriptor');
      expect(metadata).toContain('AssertionConsumerService');
      expect(metadata).toContain('https://sso.legora.com/saml/metadata');
      expect(metadata).toContain('https://sso.legora.com/auth/saml/tenant-1/acs');
      expect(metadata).toContain('SingleLogoutService');
    });

    it('should include certificate if provided', () => {
      const fakeCert = 'MIICpDCCAYwCCQD...';
      const metadata = generateSpMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        certificate: fakeCert,
      });

      expect(metadata).toContain('X509Certificate');
      expect(metadata).toContain('KeyDescriptor');
    });

    it('should escape XML special characters in entity ID', () => {
      const metadata = generateSpMetadata({
        entityId: 'https://sp.example.com/?a=1&b=2',
        acsUrl: 'https://sp.example.com/acs',
      });

      // & should be escaped to &amp;
      expect(metadata).toContain('&amp;');
      expect(metadata).not.toContain('&b=2"'); // raw & should not appear in attribute
    });

    it('should include correct NameID format', () => {
      const metadata = generateSpMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      });

      expect(metadata).toContain('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
    });

    it('should not include SLO element if not provided', () => {
      const metadata = generateSpMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
      });

      expect(metadata).not.toContain('SingleLogoutService');
    });
  });

  describe('parseXml', () => {
    it('should parse simple XML', async () => {
      const xml = '<root><child>value</child></root>';
      const result = await parseXml(xml);
      expect(result).toBeTruthy();
    });
  });
});
