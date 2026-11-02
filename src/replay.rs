// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct MemoryReplayCache {
    max: usize,
    seen: std::sync::Arc<Mutex<HashMap<String, i64>>>,
}

impl MemoryReplayCache {
    pub fn new(max_entries: usize) -> Self {
        Self { max: if max_entries == 0 { 10000 } else { max_entries }, seen: std::sync::Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn check_and_record(&self, assertion_id: &str, expires_at_ms: i64) -> Result<bool> {
        let mut seen = self.seen.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        seen.retain(|_, expires| *expires > now);
        if let Some(until) = seen.get(assertion_id) {
            if *until > now {
                return Ok(true);
            }
        }
        if seen.len() >= self.max {
            return Err(fail("replay", "the replay cache is full"));
        }
        seen.insert(assertion_id.to_string(), expires_at_ms);
        Ok(false)
    }
}
