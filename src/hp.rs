pub mod derp;
pub mod interfaces;
pub mod netcheck;
pub mod ping;
pub mod portmapper;
pub mod stun;

mod clock;
use once_cell::sync::Lazy;

use self::clock::Clock;

/// Our global clock, gets set to a fake one in tests
static CLOCK: Lazy<Clock> = Lazy::new(|| Clock::default());
