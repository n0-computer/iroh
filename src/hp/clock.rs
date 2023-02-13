use std::{fmt::Debug, ops::Deref};

use async_time_mock_tokio::MockableClock;

/// Clock to allow for testing time.
#[derive(Clone)]
pub struct Clock {
    pub inner: MockableClock,
    #[cfg(test)]
    pub controller: Option<std::sync::Arc<async_time_mock_tokio::core::TimerRegistry>>,
}

impl Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Clock");
        d.field("inner", &"MockableClock");

        #[cfg(test)]
        {
            d.field("controller", &self.controller);
        }

        d.finish()
    }
}

impl Default for Clock {
    #[cfg(test)]
    fn default() -> Self {
        let inner = MockableClock::Real;
        Self {
            inner,
            controller: None,
        }
    }
    #[cfg(not(test))]
    fn default() -> Self {
        Self {
            inner: MockableClock::Real,
        }
    }
}

impl Clock {
    #[cfg(test)]
    pub fn mock() -> Self {
        let (inner, controller) = MockableClock::mock();
        Self {
            inner,
            controller: Some(controller),
        }
    }
}

impl Deref for Clock {
    type Target = MockableClock;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
