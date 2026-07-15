use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineError {
    InvalidTimeout,
    Elapsed,
}

#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    end: Instant,
}

impl Deadline {
    pub fn after(timeout: Duration) -> Result<Self, DeadlineError> {
        if timeout.is_zero() {
            return Err(DeadlineError::InvalidTimeout);
        }
        let end = Instant::now()
            .checked_add(timeout)
            .ok_or(DeadlineError::InvalidTimeout)?;
        Ok(Self { end })
    }

    pub fn remaining(&self) -> Result<Duration, DeadlineError> {
        let remaining = self.end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(DeadlineError::Elapsed)
        } else {
            Ok(remaining)
        }
    }
}
