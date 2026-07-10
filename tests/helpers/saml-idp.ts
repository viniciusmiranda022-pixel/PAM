// IdP SAML simulado para os testes: gera um par de chaves + certificado
// autoassinado (openssl) e produz uma SAML Response com a Assertion assinada de
// verdade (xml-crypto, RSA-SHA256, c14n exclusiva). A validacao no backend e a
// de producao (@node-saml/node-saml).
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { SignedXml } from "xml-crypto";

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

export interface FakeSamlIdp {
  /** Certificado (PEM) do IdP — vai em SAML_IDP_CERT. */
  certPem: string;
  /** Constroi uma SAML Response (base64) com a Assertion assinada. */
  buildResponse: (opts: {
    inResponseTo: string;
    recipient: string; // ACS (SAML_CALLBACK_URL)
    audience: string;   // SP issuer (SAML_SP_ISSUER)
    nameId: string;
    email?: string;
    name?: string;
    groups?: string[];
    groupsAttr?: string;
  }) => string;
  cleanup: () => void;
}

/** Extrai o ID do AuthnRequest do redirect de /saml/login (HTTP-Redirect). */
export function requestIdFromLoginLocation(location: string): string {
  const samlRequest = new URL(location).searchParams.get("SAMLRequest");
  if (!samlRequest) throw new Error("SAMLRequest ausente no redirect");
  const xml = zlib.inflateRawSync(Buffer.from(samlRequest, "base64")).toString("utf8");
  const m = xml.match(/ID="([^"]+)"/);
  if (!m) throw new Error("ID nao encontrado no AuthnRequest");
  return m[1];
}

export function startFakeSamlIdp(): FakeSamlIdp {
  const dir = mkdtempSync(path.join(os.tmpdir(), "saml-idp-"));
  const keyFile = path.join(dir, "key.pem");
  const certFile = path.join(dir, "cert.pem");
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout ${keyFile} -out ${certFile} -days 1 -nodes -subj "/CN=test-idp"`,
    { stdio: "ignore" },
  );
  const keyPem = readFileSync(keyFile, "utf8");
  const certPem = readFileSync(certFile, "utf8");

  const buildResponse: FakeSamlIdp["buildResponse"] = (o) => {
    const now = new Date();
    const notBefore = new Date(now.getTime() - 60_000).toISOString();
    const notAfter = new Date(now.getTime() + 300_000).toISOString();
    const issued = now.toISOString();
    const assertionId = `_a${Math.random().toString(36).slice(2)}`;
    const responseId = `_r${Math.random().toString(36).slice(2)}`;
    const groupsAttr = o.groupsAttr ?? "http://schemas.xmlsoap.org/claims/Group";

    const attrs: string[] = [];
    if (o.email) attrs.push(attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", [o.email]));
    if (o.name) attrs.push(attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", [o.name]));
    if (o.groups?.length) attrs.push(attr(groupsAttr, o.groups));

    const assertion =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${issued}">` +
      `<saml:Issuer>test-idp</saml:Issuer>` +
      `<saml:Subject>` +
      `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${esc(o.nameId)}</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData InResponseTo="${o.inResponseTo}" Recipient="${esc(o.recipient)}" NotOnOrAfter="${notAfter}"/>` +
      `</saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notAfter}">` +
      `<saml:AudienceRestriction><saml:Audience>${esc(o.audience)}</saml:Audience></saml:AudienceRestriction>` +
      `</saml:Conditions>` +
      `<saml:AuthnStatement AuthnInstant="${issued}"><saml:AuthnContext>` +
      `<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>` +
      `</saml:AuthnContext></saml:AuthnStatement>` +
      (attrs.length ? `<saml:AttributeStatement>${attrs.join("")}</saml:AttributeStatement>` : "") +
      `</saml:Assertion>`;

    const response =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
      `ID="${responseId}" Version="2.0" IssueInstant="${issued}" Destination="${esc(o.recipient)}" InResponseTo="${o.inResponseTo}">` +
      `<saml:Issuer>test-idp</saml:Issuer>` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      assertion +
      `</samlp:Response>`;

    const sig = new SignedXml({
      privateKey: keyPem,
      signatureAlgorithm: RSA_SHA256,
      canonicalizationAlgorithm: EXC_C14N,
    });
    sig.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      transforms: [ENVELOPED, EXC_C14N],
      digestAlgorithm: SHA256,
    });
    // A assinatura vai DENTRO da Assertion, logo apos o Issuer dela.
    sig.computeSignature(response, {
      location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" },
    });
    return Buffer.from(sig.getSignedXml()).toString("base64");
  };

  return { certPem, buildResponse, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function esc(s: string): string {
  return s.replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c] as string));
}
function attr(name: string, values: string[]): string {
  const vs = values.map((v) => `<saml:AttributeValue>${esc(v)}</saml:AttributeValue>`).join("");
  return `<saml:Attribute Name="${name}">${vs}</saml:Attribute>`;
}
