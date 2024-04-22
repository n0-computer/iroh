// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use s2n_quic_core::time::{self, Timestamp};
use tokio::time::{sleep_until, Instant, Sleep};

#[derive(Clone, Debug)]
pub struct Clock(Instant);

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl time::Clock for Clock {
    #[inline]
    fn get_time(&self) -> time::Timestamp {
        let duration = self.0.elapsed();
        unsafe {
            // Safety: time duration is only derived from a single `Instant`
            time::Timestamp::from_duration(duration)
        }
    }
}

impl time::ClockWithTimer for Clock {
    type Timer = Timer;

    #[inline]
    fn timer(&self) -> Timer {
        Timer::new(self.clone())
    }
}

#[derive(Debug)]
pub struct Timer {
    /// A reference to the current clock
    clock: Clock,
    /// The `Instant` at which the timer should expire
    target: Option<Instant>,
    /// The handle to the timer entry in the tokio runtime
    sleep: Pin<Box<Sleep>>,
}

impl Timer {
    fn new(clock: Clock) -> Self {
        /// We can't create a timer without first arming it to something, so just set it to 1s in
        /// the future.
        const INITIAL_TIMEOUT: Duration = Duration::from_secs(1);

        let target = clock.0 + INITIAL_TIMEOUT;
        let sleep = Box::pin(sleep_until(target));
        Self {
            clock,
            target: Some(target),
            sleep,
        }
    }
}

impl time::clock::Timer for Timer {
    #[inline]
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<()> {
        // Only poll the inner timer if we have a target set
        if self.target.is_none() {
            return Poll::Pending;
        }

        let res = self.sleep.as_mut().poll(cx);

        if res.is_ready() {
            // clear the target after it fires, otherwise we'll endlessly wake up the task
            self.target = None;
        }

        res
    }

    #[inline]
    fn update(&mut self, timestamp: Timestamp) {
        let delay = unsafe {
            // Safety: the same clock epoch is being used
            timestamp.as_duration()
        };

        // floor the delay to milliseconds to reduce timer churn
        let delay = Duration::from_millis(delay.as_millis() as u64);

        // add the delay to the clock's epoch
        let next_time = self.clock.0 + delay;

        // If the target hasn't changed then don't do anything
        if Some(next_time) == self.target {
            return;
        }

        // if the clock has changed let the sleep future know
        self.sleep.as_mut().reset(next_time);
        self.target = Some(next_time);
    }
}
