use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::authz::AuthzContext;

const TTL: Duration = Duration::from_secs(30);

struct Entry {
    stored_at: Instant,
    context: AuthzContext,
}

pub struct AuthzCache {
    entries: Mutex<HashMap<Uuid, Entry>>,
}

impl AuthzCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn get(&self, user_id: Uuid) -> Option<AuthzContext> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&user_id)?;
        if entry.stored_at.elapsed() > TTL {
            return None;
        }
        Some(entry.context.clone())
    }

    pub fn put(&self, user_id: Uuid, context: AuthzContext) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                user_id,
                Entry {
                    stored_at: Instant::now(),
                    context,
                },
            );
        }
    }

    pub fn invalidate(&self, user_id: Uuid) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&user_id);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

impl Default for AuthzCache {
    fn default() -> Self {
        Self::new()
    }
}
