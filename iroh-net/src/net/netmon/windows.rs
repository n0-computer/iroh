use std::collections::HashSet;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::warn;
use windows::Win32::Foundation::HANDLE;

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
    cb_handler: CallbackHandler,
}

impl RouteMonitor {
    pub async fn new(sender: mpsc::Sender<Message>) -> Result<Self> {
        // Register two callbacks with the windows api
        let cb_handler = CallbackHandler::default();

        // 1. Unicast Address Changes
        cb_handler.register_unicast_address_change_callback(Box::new(|| {
            if let Err(err) = sender.blocking_send(Message) {
                warn!("unable to send: unicast change notification", err);
            }
        }));

        // 2. Route Changes

        // TODO

        Ok(RouteMonitor { cb_handler })
    }
}

pub(super) fn is_interesting_interface(_name: &str) -> bool {
    true
}

struct CallbackHandler {
    /// stores the  `Handle`s for the callbacks.
    // `Handle` is not hashable, so store the underlying `isize`.
    unicast_callbacks: HashSet<isize>,
}

impl Drop for CallbackHandler {
    fn drop(&mut self) {
        // Make sure to unregister all callbacks left.
        let handles: Vec<_> = self
            .unicast_callbacks
            .iter()
            .map(|h| UnicastCallbackHandler(Handle(*h)))
            .collect();

        for handle in handles {
            self.unregister_unicast_address_change_callback(handle).ok(); // best effort
        }
    }
}

struct UnicastCallbackHandle(Handle);

impl CallbackHandler {
    fn register_unicast_address_change_callback(
        &mut self,
        cb: Box<dyn Fn()>,
    ) -> Result<UnicastCallbackHandle> {
        let mut handle = Handle::default();

        unsafe {
            windows::Win32::NetworkManagement::IpHelper::NotifyUnicastIpAddressChange(
                windows::Win32::Networking::WinSock::AF_UNSPEC,
                Some(unicast_change_callback),
                Some(cb as *const _ as *const c_void), // context
                false,                                 // initial notification,
                &mut handle,
            )?;
        }

        self.unicast_callbacks.insert(handle.0);

        Ok(UnicastCallbackHandle(handle))
    }

    fn unregister_unicast_address_change_callback(
        &mut self,
        handle: UnicastCallbackHandle,
    ) -> Result<()> {
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(handle.handle)?;
        }
        self.unicast_callbacks.remove(handle.handle.0);

        Ok(())
    }
}

unsafe extern "system" fn unicast_change_callback(
    callercontext: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    notificationtype: MIB_NOTIFICATION_TYPE,
) {
    if callercontext.is_null() {
        // Nothing we can do
        return;
    }

    let cb: Box<dyn Fn()> = &*callercontext;
    cb();
}
