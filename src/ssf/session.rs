// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::names::DEFAULT_SUBJECT_ATTRIBUTE;
use crate::token::Login;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const MAIL: &[&str] = &[
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
];

#[derive(Clone, Debug)]
pub struct Session {
    pub local_id: String,
    pub person: String,
    pub email: String,
    pub idp_session: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct MemorySessionIndex {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    sessions: HashMap<String, Session>,
    max: usize,
}

impl MemorySessionIndex {
    pub fn new(max_entries: usize) -> Self {
        Self { inner: Arc::new(Mutex::new(Inner { sessions: HashMap::new(), max: if max_entries == 0 { 100_000 } else { max_entries } })) }
    }

    pub fn add(&self, mut session: Session) {
        let mut inner = self.inner.lock().unwrap();
        if inner.sessions.len() >= inner.max && !inner.sessions.contains_key(&session.local_id) {
            let now = Utc::now();
            inner.sessions.retain(|_, value| value.expires_at.is_none_or(|expires| expires > now));
            while inner.sessions.len() >= inner.max {
                if let Some(key) = inner.sessions.keys().next().cloned() { inner.sessions.remove(&key); } else { break; }
            }
        }
        if !session.email.is_empty() { session.email = session.email.to_ascii_lowercase(); }
        inner.sessions.insert(session.local_id.clone(), session);
    }

    pub fn remove(&self, local_id: &str) {
        self.inner.lock().unwrap().sessions.remove(local_id);
    }

    fn find(&self, mut matches: impl FnMut(&Session) -> bool) -> Vec<String> {
        let mut inner = self.inner.lock().unwrap();
        let now = Utc::now();
        let expired: Vec<_> = inner.sessions.iter().filter(|(_, value)| value.expires_at.is_some_and(|expires| expires <= now)).map(|(key, _)| key.clone()).collect();
        for key in expired { inner.sessions.remove(&key); }
        inner.sessions.iter().filter(|(_, value)| matches(value)).map(|(key, _)| key.clone()).collect()
    }

    pub fn by_person(&self, person: &str) -> Vec<String> {
        self.find(|session| session.person == person)
    }

    pub fn by_email(&self, email: &str) -> Vec<String> {
        let wanted = email.to_ascii_lowercase();
        self.find(|session| session.email == wanted)
    }

    pub fn by_idp_session(&self, idp_session: &str) -> Vec<String> {
        self.find(|session| session.idp_session == idp_session)
    }
}

pub fn tracked_from(local_id: &str, login: Option<&Login>, subject_attribute: &str, expires_at: Option<DateTime<Utc>>) -> Session {
    let subject_attribute = if subject_attribute.is_empty() { DEFAULT_SUBJECT_ATTRIBUTE } else { subject_attribute };
    let person = login.and_then(|item| item.attributes.get(subject_attribute)).and_then(|values| values.first()).cloned().unwrap_or_default();
    let mut email = String::new();
    if let Some(login) = login {
        for name in MAIL {
            if let Some(value) = login.attributes.get(*name).and_then(|values| values.first()) {
                if !value.is_empty() { email = value.clone(); break; }
            }
        }
        if email.is_empty() && login.name_id_format.as_deref() == Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") {
            email = login.name_id.clone();
        }
    }
    Session {
        local_id: local_id.to_string(),
        person,
        email,
        idp_session: login.and_then(|item| item.session_index.clone()).unwrap_or_default(),
        expires_at: expires_at.or_else(|| login.and_then(|item| item.session_not_on_or_after)),
    }
}
