use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use libc::c_void;
use tracing::{debug, warn};
use windows::Win32::{
    Foundation::{BOOLEAN, HANDLE as Handle},
    NetworkManagement::IpHelper::{MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW},
};

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
    cb_handler: CallbackHandler,
}

impl RouteMonitor {
    pub async fn new(sender: flume::Sender<Message>) -> Result<Self> {
        // Register two callbacks with the windows api
        let mut cb_handler = CallbackHandler::default();

        // 1. Unicast Address Changes
        let s = sender.clone();
        cb_handler.register_unicast_address_change_callback(Box::new(move || {
            if let Err(err) = s.send(Message) {
                warn!("unable to send: unicast change notification: {:?}", err);
            }
        }))?;

        // 2. Route Changes

        // TODO

        Ok(RouteMonitor { cb_handler })
    }
}

pub(super) fn is_interesting_interface(_name: &str) -> bool {
    true
}

#[derive(derive_more::Debug, Default)]
struct CallbackHandler {
    /// stores the  `Handle`s for the callbacks.
    // `Handle` is not hashable, so store the underlying `isize`.
    #[debug("HashMap<isize, Arc<UnicastCallback>")]
    unicast_callbacks: HashMap<isize, Arc<UnicastCallback>>,
}

impl Drop for CallbackHandler {
    fn drop(&mut self) {
        // Make sure to unregister all callbacks left.
        let handles: Vec<_> = self
            .unicast_callbacks
            .keys()
            .map(|h| UnicastCallbackHandle(Handle(*h)))
            .collect();

        for handle in handles {
            self.unregister_unicast_address_change_callback(handle).ok(); // best effort
        }
    }
}

struct UnicastCallbackHandle(Handle);

type UnicastCallback = Box<dyn Fn() + Send + Sync + 'static>;

impl CallbackHandler {
    fn register_unicast_address_change_callback(
        &mut self,
        cb: UnicastCallback,
    ) -> Result<UnicastCallbackHandle> {
        debug!("registering callback");
        let mut handle = Handle::default();
        let cb = Arc::new(cb);
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::NotifyUnicastIpAddressChange(
                windows::Win32::Networking::WinSock::AF_UNSPEC,
                Some(unicast_change_callback),
                Some(Arc::as_ptr(&cb) as *const c_void), // context
                BOOLEAN::from(false),                    // initial notification,
                &mut handle,
            )?;
        }

        self.unicast_callbacks.insert(handle.0, cb);

        Ok(UnicastCallbackHandle(handle))
    }

    fn unregister_unicast_address_change_callback(
        &mut self,
        handle: UnicastCallbackHandle,
    ) -> Result<()> {
        debug!("unregistering callback");
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(handle.0)?;
        }
        self.unicast_callbacks.remove(&handle.0 .0);

        Ok(())
    }
}

unsafe extern "system" fn unicast_change_callback(
    callercontext: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    notificationtype: MIB_NOTIFICATION_TYPE,
) {
    println!(
        "unicast_change_callback: {:?}, {:?}, {:?}",
        callercontext, row, notificationtype
    );
    if callercontext.is_null() {
        // Nothing we can do
        return;
    }
    let callercontext = callercontext as *const UnicastCallback;
    println!("got caller context pointer");
    let cb = &*callercontext;
    println!("calling cb");
    cb();
}
