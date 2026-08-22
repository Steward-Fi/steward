import { signXml } from "@node-saml/node-saml/lib/xml";

export const TEST_IDP_CERT = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUKybcclhsj+h8d+H36sVUjlfVXkgwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVU3Rld2FyZCBTQU1MIFRlc3QgSWRQMB4XDTI2MDUyOTAz
MjYyMloXDTM2MDUyNjAzMjYyMlowIDEeMBwGA1UEAwwVU3Rld2FyZCBTQU1MIFRl
c3QgSWRQMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj/bmD2BOnJYE
69J2S8w56ACMNBY9YADrpISPKCSF8dbcb3MtpKdK9Rd32VQbktLbDIJ5Hx0KVCGk
uVKQ3AljypPmc9QggFeIeGhSGIv4qj91mR1r5T7FtT/Uu09QhOj93rCJXmigxS+H
nW9m+NAyspZnrI2c/k0nAzYdoCRurHq4eApQANC3MsSAGLLyVbFsGpHyeJZEoURv
Os0B06OBRnPlmOeQnWJPVOcPETePy72IlIkxjUa/mSzgjPvzyKYw+GtabcHkEfgM
EK2MAsEa0hELtylolHZ1Z4dMF2uY+XETX7TI+jM0gHUbsVbIBjVJeBl0Y1l16FSR
E16dSaTY0wIDAQABo1MwUTAdBgNVHQ4EFgQUjS1h9KMehQHPwvAgPvKnUtXOn4ow
HwYDVR0jBBgwFoAUjS1h9KMehQHPwvAgPvKnUtXOn4owDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAIrIixamp28P8EnXSnN+qD2wjkaMjx+CMVfYn
K0ybv7U1cV7vafdY7D2P9r+vfYB9TFVsi96Hn44okWRcS+AAd0Fst+yg1p173bDU
WWCIzrnf31jsP/OVtQi1k2vTBmtXFtY394yr29/pwHIysJ6+9+98s745MHQUdF40
qlVtzbU3DtjURtzqi3OQDpxTmADAHdU6UoeVTOuMDNQryJV9IMf7szko15oBzQJv
xQpVMiAAIZ00Y/Q/hFsXPOLgIFtc3/O0euRQ2zkvk8eqBewjduyaP5dkHfySVfoa
fDIFQJSzQbapRCV/a6SwPOKV5oD3ElPqkQHIt/U+ezTY0KuCcA==
-----END CERTIFICATE-----`;

const TEST_IDP_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCP9uYPYE6clgTr
0nZLzDnoAIw0Fj1gAOukhI8oJIXx1txvcy2kp0r1F3fZVBuS0tsMgnkfHQpUIaS5
UpDcCWPKk+Zz1CCAV4h4aFIYi/iqP3WZHWvlPsW1P9S7T1CE6P3esIleaKDFL4ed
b2b40DKylmesjZz+TScDNh2gJG6serh4ClAA0LcyxIAYsvJVsWwakfJ4lkShRG86
zQHTo4FGc+WY55CdYk9U5w8RN4/LvYiUiTGNRr+ZLOCM+/PIpjD4a1ptweQR+AwQ
rYwCwRrSEQu3KWiUdnVnh0wXa5j5cRNftMj6MzSAdRuxVsgGNUl4GXRjWXXoVJET
Xp1JpNjTAgMBAAECggEAEqR/o5DDx/Xf/+8VGo5Wa/tbgd3kvMCMberXOZ+L04a7
V5isBHJq0So6KY6BXkCn1QrgRxh/nz1sE1jkdq9QmN8Q11b/jnRyBlrxUUnEPbz8
rC3p1u82CFk9DF8iUikfFu34G/L4lBBU7hzgUhVukJR21cV7ha2AASPKL6ldcOrm
/GHGRqXy7yuRprSN4S5pIsjVhLrOM2QL56VekVibyvCcVyP2mTSVFkTgc7keMBe/
biaR2L1uqrpWDRz5PGKD4HQzbc5huwcP/R9PtEvx8qJTF7K7z5/pdVwE+G/STqvd
e6SbsFyplazilNW73Nx6V+B1IBbZtH9PyEHq7TkLgQKBgQDGG4Gf3SnDrryfj9no
JLoCZbMVIzdRBBrupyiCyCFNVzOl0CFGHMcjUg9gK9twZnCzlBdS4NSytFRuGEZ5
s70vD6WXi3LJLE1ySxZ2r/JKSlHpiSzIVc73ke8G0m1bfQl3abRvpLJ3QhPAcBIx
eJu9Lv270icCmllVjfjONFavkQKBgQC6CO8Wm2FSrr/RgQ8eNWwPsszWP3D2UqWu
t+HtATy1ao2dJG07WCtpdiygRyrqjOYLUmSY6a6ZauiXjihGMnq3aazUE+0QE19g
+cbMqGgQuVRgvbfTDUXDvQ5oIF578+nBnyTEptt0+nRpuPP3XV2k7gGMOnGAWwWu
Zvr4F+FYIwKBgQCbc8YZjdBR7vGwO48ALKGRdAA8m++yMQh5MM4HIceQCtdKS7Fw
dPCGdMP/8So2Xwwcvh43OJluyTZfVckngrT3Es4bxp8B4TO8ddNgutvjE8KHAM8V
PNA1UFxB/Ck32zvsahPeb1xjXIRnQwnjrAJ5R0Bve46E6l0jV05fcI59IQKBgQCQ
cA1JjRwT+Q9/Fufo+WtMCPOWyKzo4qQ2shgcTmCXLgKDZlvUvpD+Eb12N6svbnPR
iIgIXS6teN7bhIjqb5jtvINuKYZee9wKzAM4tOwPSAUmE0ac+2oWHjwIRlF1hZwR
M4F1mWM8QJSP3QS2Iuxo+E2FVX74PDN+BACJDOlt5wKBgDpJ5fKbawRZjuF70IjT
nCZBXYblR/x/lN9gvgNvPTcB4a3blk2bzbHXnrBND+Jzvq3O/DU1dkWr/Y/8FzqA
csqQ2vt05YmH3WaBuXw3obBjwSmSRJ5/fn6KeACxi0yGg2rPdMKC8/mZQ04B59RJ
Q6KFw30AGA+dh9xnxw4ZPxy0
-----END PRIVATE KEY-----`;

export interface SignedSamlResponseOptions {
  requestId: string;
  assertionId: string;
  responseId?: string;
  issuer: string;
  audience: string;
  acsUrl: string;
  email: string;
  destination?: string;
  recipient?: string;
}

function signElement(xml: string, elementName: "Assertion" | "Response"): string {
  return signXml(
    xml,
    `//*[local-name(.)='${elementName}']`,
    {
      reference: `//*[local-name(.)='${elementName}']/*[local-name(.)='Issuer']`,
      action: "after",
    },
    {
      privateKey: TEST_IDP_PRIVATE_KEY,
      publicCert: TEST_IDP_CERT,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
    },
  );
}

export function signedSamlResponse(options: SignedSamlResponseOptions): string {
  const issueInstant = new Date().toISOString();
  const notBefore = new Date(Date.now() - 60_000).toISOString();
  const notOnOrAfter = new Date(Date.now() + 240_000).toISOString();
  const destination = options.destination ?? options.acsUrl;
  const recipient = options.recipient ?? options.acsUrl;
  const assertion = [
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${options.assertionId}" Version="2.0" IssueInstant="${issueInstant}">`,
    `<saml:Issuer>${options.issuer}</saml:Issuer>`,
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${options.email}</saml:NameID>`,
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${recipient}"/></saml:SubjectConfirmation></saml:Subject>`,
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${options.audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`,
    `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="_session-${options.assertionId}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
    `<saml:AttributeStatement><saml:Attribute Name="ID"><saml:AttributeValue>${options.assertionId}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email"><saml:AttributeValue>${options.email}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>Engineering</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`,
    `</saml:Assertion>`,
  ].join("");
  const signedAssertion = signElement(assertion, "Assertion");
  const response = [
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${options.responseId ?? `_response-${options.assertionId}`}" Version="2.0" IssueInstant="${issueInstant}" Destination="${destination}" InResponseTo="${options.requestId}">`,
    `<saml:Issuer>${options.issuer}</saml:Issuer>`,
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`,
    signedAssertion,
    `</samlp:Response>`,
  ].join("");
  return Buffer.from(signElement(response, "Response"), "utf8").toString("base64");
}
