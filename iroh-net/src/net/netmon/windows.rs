use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use libc::c_void;
use tracing::{debug, warn};
use windows::Win32::{
    Foundation::{BOOLEAN, HANDLE as Handle},
    NetworkManagement::IpHelper::{
        MIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    },
};

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
    #[allow(dead_code)]
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
        cb_handler.register_route_change_callback(Box::new(move || {
            if let Err(err) = sender.send(Message) {
                warn!("unable to send: route change notification: {:?}", err);
            }
        }))?;

        Ok(RouteMonitor { cb_handler })
    }
}

pub(super) fn is_interesting_interface(_name: &str) -> bool {
    true
}

/// Manages callbacks registered with the win32 networking API.
#[derive(derive_more::Debug, Default)]
struct CallbackHandler {
    /// Stores the callbacks and `Handle`s for unicast.
    // `Handle` is not hashable, so store the underlying `isize`.
    #[debug("HashMap<isize, UnicastCallback")]
    unicast_callbacks: HashMap<isize, Arc<UnicastCallback>>,
    /// Stores the callbacks and `Handle`s for route.
    // `Handle` is not hashable, so store the underlying `isize`.
    #[debug("HashMap<isize, RouteCallback")]
    route_callbacks: HashMap<isize, Arc<RouteCallback>>,
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

        let handles: Vec<_> = self
            .route_callbacks
            .keys()
            .map(|h| RouteCallbackHandle(Handle(*h)))
            .collect();

        for handle in handles {
            self.unregister_route_change_callback(handle).ok(); // best effort
        }
    }
}

struct UnicastCallbackHandle(Handle);
type UnicastCallback = Box<dyn Fn() + Send + Sync + 'static>;

struct RouteCallbackHandle(Handle);
type RouteCallback = Box<dyn Fn() + Send + Sync + 'static>;

impl CallbackHandler {
    fn register_unicast_address_change_callback(
        &mut self,
        cb: UnicastCallback,
    ) -> Result<UnicastCallbackHandle> {
        debug!("registering unicast callback");
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
        debug!("unregistering unicast callback");
        if self.unicast_callbacks.remove(&handle.0 .0).is_some() {
            unsafe {
                windows::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(handle.0)?;
            }
        }

        Ok(())
    }

    fn register_route_change_callback(&mut self, cb: RouteCallback) -> Result<RouteCallbackHandle> {
        debug!("registering route change callback");
        let mut handle = Handle::default();
        let cb = Arc::new(cb);
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::NotifyRouteChange2(
                windows::Win32::Networking::WinSock::AF_UNSPEC,
                Some(route_change_callback),
                Arc::as_ptr(&cb) as *const c_void, // context
                BOOLEAN::from(false),              // initial notification,
                &mut handle,
            )?;
        }

        self.route_callbacks.insert(handle.0, cb);

        Ok(RouteCallbackHandle(handle))
    }

    fn unregister_route_change_callback(&mut self, handle: RouteCallbackHandle) -> Result<()> {
        debug!("unregistering route callback");
        if self.route_callbacks.remove(&handle.0 .0).is_some() {
            unsafe {
                windows::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(handle.0)?;
            }
        }

        Ok(())
    }
}

unsafe extern "system" fn unicast_change_callback(
    callercontext: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _notificationtype: MIB_NOTIFICATION_TYPE,
) {
    if callercontext.is_null() {
        // Nothing we can do
        return;
    }
    let callercontext = callercontext as *const UnicastCallback;
    let cb = &*callercontext;
    cb();
}

unsafe extern "system" fn route_change_callback(
    callercontext: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _notificationtype: MIB_NOTIFICATION_TYPE,
) {
    if callercontext.is_null() {
        // Nothing we can do
        return;
    }
    let callercontext = callercontext as *const RouteCallback;
    let cb = &*callercontext;
    cb();
}
