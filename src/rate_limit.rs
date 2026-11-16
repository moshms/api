use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_FAILURES: u32 = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
const BLOCK_DURATION: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
struct Entry {
    failures: u32,
    last_failure: Instant,
    blocked_until: Option<Instant>,
}

pub struct LoginLimiter {
    entries: Mutex<HashMap<String, Entry>>,
}

impl LoginLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn blocked_for(&self, key: &str) -> Option<Duration> {
        let mut entries = self.entries.lock().ok()?;
        let now = Instant::now();
        entries.retain(|_, entry| {
            entry.blocked_until.is_some_and(|until| until > now)
                || now.duration_since(entry.last_failure) < FAILURE_WINDOW
        });

        let entry = entries.get(key)?;
        entry
            .blocked_until
            .filter(|until| *until > now)
            .map(|until| until.duration_since(now))
    }

    pub fn record_failure(&self, key: &str) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        let entry = entries.entry(key.to_owned()).or_insert_with(|| Entry {
            failures: 0,
            last_failure: now,
            blocked_until: None,
        });

        if entry.blocked_until.is_some_and(|until| until > now) {
            return;
        }

        if now.duration_since(entry.last_failure) >= FAILURE_WINDOW {
            entry.failures = 0;
        }

        entry.failures += 1;
        entry.last_failure = now;

        if entry.failures >= MAX_FAILURES {
            entry.blocked_until = Some(now + BLOCK_DURATION);
        }
    }

    pub fn record_success(&self, key: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::LoginLimiter;

    #[test]
    fn blocks_after_repeated_failures_and_clears_on_success() {
        let limiter = LoginLimiter::new();
        for _ in 0..5 {
            limiter.record_failure("admin:127.0.0.1");
        }

        assert!(limiter.blocked_for("admin:127.0.0.1").is_some());
        limiter.record_success("admin:127.0.0.1");
        assert!(limiter.blocked_for("admin:127.0.0.1").is_none());
    }
}
