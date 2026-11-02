// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::fmt;

#[derive(Debug, Clone)]
pub struct WsFedError {
    pub code: String,
    pub message: String,
}

impl WsFedError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.to_string(), message: message.into() }
    }
}

impl fmt::Display for WsFedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WsFedError {}

pub fn fail(code: &str, message: impl Into<String>) -> WsFedError {
    WsFedError::new(code, message)
}

pub type Result<T> = std::result::Result<T, WsFedError>;
