// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const SAML1: &str = "urn:oasis:names:tc:SAML:1.0:assertion";
pub const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
pub const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
pub const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
pub const FED: &str = "http://docs.oasis-open.org/wsfed/federation/200706";
pub const TRUST2005: &str = "http://schemas.xmlsoap.org/ws/2005/02/trust";
pub const TRUST13: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
pub const WSA: &str = "http://www.w3.org/2005/08/addressing";
pub const WSA2004: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
pub const WSP: &str = "http://schemas.xmlsoap.org/ws/2004/09/policy";
pub const WSP15: &str = "http://www.w3.org/ns/ws-policy";
pub const WSU: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
pub const SAML2_TOKEN: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const SAML2_TOKEN_WSS: &str = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const DEFAULT_SUBJECT_ATTRIBUTE: &str =
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
pub const C14N10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N10_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

pub fn is_saml2_token(value: &str) -> bool {
    value == SAML2_TOKEN || value == SAML2_TOKEN_WSS
}
