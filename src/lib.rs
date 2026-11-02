// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

pub mod cli;
pub mod config;
pub mod demo;
pub mod encryption;
pub mod error;
pub mod httpclient;
pub mod metadata;
pub mod names;
pub mod relying_party;
pub mod replay;
pub mod signature;
pub mod ssf;
pub mod token;
pub mod x509util;
pub mod xml;

pub use config::{read_config_file, resolve_config, Resolved};
pub use error::{fail, Result, WsFedError};
pub use metadata::{read_idp_metadata, write_rp_metadata, IdpMetadata};
pub use names::{
    CM_BEARER, DEFAULT_SUBJECT_ATTRIBUTE, RSA_SHA256, STATUS_SUCCESS,
};
pub use relying_party::{LoginOptions, LoginRequest, RelyingParty, ReplyBody, ReplyRequest};
pub use signature::sign_enveloped;
pub use ssf::{events, SignalsReceiver};
pub use token::Login;
pub use x509util::{create_self_signed_key_pair, KeyPair};

pub fn from_file(path: &str, overrides: Option<serde_json::Map<String, serde_json::Value>>) -> Result<RelyingParty> {
    RelyingParty::from_file(path, overrides)
}

pub fn string_ptr(value: impl Into<String>) -> Option<String> {
    Some(value.into())
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod test_rp;
#[cfg(test)]
mod test_x509;
#[cfg(test)]
mod test_ssf;
#[cfg(test)]
mod test_http;
#[cfg(test)]
mod test_configure;
#[cfg(test)]
mod test_trust_chain;
#[cfg(test)]
mod test_plain_http;
