//! Internal utilities to support testing.

pub mod hexdump;
pub mod logging;

// #[derive(derive_more::Debug)]
#[allow(missing_debug_implementations)]
pub struct CallOnDrop(Option<Box<dyn FnOnce()>>);

impl CallOnDrop {
    pub fn new(f: impl FnOnce() + 'static) -> Self {
        Self(Some(Box::new(f)))
    }
}

impl Drop for CallOnDrop {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
