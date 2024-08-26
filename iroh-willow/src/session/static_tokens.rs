use std::{
    cell::RefCell,
    future::poll_fn,
    rc::Rc,
    task::{ready, Poll},
};

use tokio::sync::mpsc;

use crate::proto::{
    data_model::{AuthorisationToken, AuthorisedEntry, Entry},
    wgps::{DynamicToken, SetupBindStaticToken, StaticToken, StaticTokenHandle},
};

use super::{resource::ResourceMap, Error};

#[derive(Debug, Clone)]
pub struct StaticTokenSender {
    ours: Rc<RefCell<ResourceMap<StaticTokenHandle, StaticToken>>>,
    sender: mpsc::Sender<SetupBindStaticToken>,
}

impl StaticTokenSender {
    pub fn new(sender: mpsc::Sender<SetupBindStaticToken>) -> Self {
        Self {
            ours: Rc::new(RefCell::new(ResourceMap::default())),
            sender,
        }
    }

    pub async fn bind_ours_if_new(
        &self,
        static_token: StaticToken,
    ) -> Result<StaticTokenHandle, Error> {
        let (handle, is_new) = { self.ours.borrow_mut().bind_if_new(static_token.clone()) };
        if is_new {
            let msg = SetupBindStaticToken { static_token };
            self.sender.send(msg).await?;
        }
        Ok(handle)
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticTokenReceiver {
    theirs: Rc<RefCell<ResourceMap<StaticTokenHandle, StaticToken>>>,
}

impl StaticTokenReceiver {
    pub fn bind_theirs(&self, token: StaticToken) {
        self.theirs.borrow_mut().bind(token);
    }

    pub async fn authorise_entry_eventually(
        &self,
        entry: Entry,
        static_token_handle: StaticTokenHandle,
        dynamic_token: DynamicToken,
    ) -> Result<AuthorisedEntry, Error> {
        let inner = self.theirs.clone();
        let static_token = poll_fn(move |cx| {
            let mut inner = inner.borrow_mut();
            let token = ready!(inner.poll_get_eventually(static_token_handle, cx));
            Poll::Ready(token.clone())
        })
        .await;

        let token = AuthorisationToken::new(static_token.0, dynamic_token);
        let authorised_entry = AuthorisedEntry::new(entry, token)?;
        Ok(authorised_entry)
    }
}
