use std::ops::Deref;

use async_time_mock_tokio::MockableClock;

/// Clock to allow for testing time.
pub struct Clock {
    pub inner: MockableClock,
    #[cfg(test)]
    pub controller: std::sync::Arc<async_time_mock_tokio::core::TimerRegistry>,
}

impl Default for Clock {
    #[cfg(test)]
    fn default() -> Self {
        let (inner, controller) = MockableClock::mock();
        Self { inner, controller }
    }
    #[cfg(not(test))]
    fn default() -> Self {
        Self {
            inner: MockableClock::Real,
        }
    }
}

impl Deref for Clock {
    type Target = MockableClock;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
