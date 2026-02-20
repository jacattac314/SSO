/**
 * XML utilities for SAML metadata generation and parsing.
 */
import { parseStringPromise, Builder } from 'xml2js';

export async function parseXml(xml: string): Promise<Record<string, unknown>> {
  return parseStringPromise(xml, {
    explicitArray: false,
    ignoreAttrs: false,
    mergeAttrs: true,
  }) as Promise<Record<string, unknown>>;
}

export function buildXml(obj: Record<string, unknown>): string {
  const builder = new Builder({
    xmldec: { version: '1.0', encoding: 'UTF-8' },
  });
  return builder.buildObject(obj);
}

/**
 * Generates SAML SP metadata XML for a tenant configuration.
 */
export function generateSpMetadata(params: {
  entityId: string;
  acsUrl: string;
  sloUrl?: string;
  certificate?: string;
  nameIdFormat?: string;
  organizationName?: string;
}): string {
  const {
    entityId,
    acsUrl,
    sloUrl,
    certificate,
    nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    organizationName = 'Legora',
  } = params;

  const certStripped = certificate
    ? certificate
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s/g, '')
    : undefined;

  const keyDescriptor = certStripped
    ? `
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${certStripped}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${certStripped}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>`
    : '';

  const sloElement = sloUrl
    ? `
    <md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${escapeXml(sloUrl)}" />`
    : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${escapeXml(entityId)}"
  validUntil="${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ${keyDescriptor}
    ${sloElement}
    <md:NameIDFormat>${escapeXml(nameIdFormat)}</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${escapeXml(acsUrl)}"
      index="1"
      isDefault="true" />
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">${escapeXml(organizationName)}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">${escapeXml(organizationName)}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://legora.com</md:OrganizationURL>
  </md:Organization>
</md:EntityDescriptor>`;
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
