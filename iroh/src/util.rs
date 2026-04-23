//! Utilities used in [`iroh`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;

/// A future which may not be present.
///
/// This is a single type which may optionally contain a future.  If there is no inner
/// future polling will always return [`Poll::Pending`].
///
/// The [`Default`] impl will create a [`MaybeFuture`] without an inner.
#[derive(Default, Debug)]
#[pin_project(project = MaybeFutureProj, project_replace = MaybeFutureProjReplace)]
pub(crate) enum MaybeFuture<T> {
    /// Future to be polled.
    Some(#[pin] T),
    #[default]
    None,
}

impl<T> MaybeFuture<T> {
    /// Creates a [`MaybeFuture`] without an inner future.
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// Sets the future to None again.
    pub(crate) fn set_none(mut self: Pin<&mut Self>) {
        self.as_mut().project_replace(Self::None);
    }

    /// Sets a new future.
    pub(crate) fn set_future(mut self: Pin<&mut Self>, fut: T) {
        self.as_mut().project_replace(Self::Some(fut));
    }

    /// Returns `true` if the inner is empty.
    pub(crate) fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns `true` if the inner contains a future.
    pub(crate) fn is_some(&self) -> bool {
        matches!(self, Self::Some(_))
    }
}

impl<T: Future> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut().project();
        let poll_res = match this {
            MaybeFutureProj::Some(ref mut t) => t.as_mut().poll(cx),
            MaybeFutureProj::None => Poll::Pending,
        };
        match poll_res {
            Poll::Ready(val) => {
                self.as_mut().project_replace(Self::None);
                Poll::Ready(val)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(wasm_browser)]
pub(crate) fn reqwest_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

/// Creates a reqwest client builder that always uses the rustls backend, unless we
/// are in a browser context, where that is not supported.
#[cfg(not(wasm_browser))]
pub(crate) fn reqwest_client_builder(
    tls_client_config: rustls::ClientConfig,
    dns_resolver: crate::dns::DnsResolver,
) -> reqwest::ClientBuilder {
    use std::sync::Arc;

    use self::reqwest_dns_resolver::ReqwestDnsResolver;

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_client_config)
        .dns_resolver(Arc::new(ReqwestDnsResolver(dns_resolver)))
}

#[cfg(not(wasm_browser))]
mod reqwest_dns_resolver {
    //! Implementation of [`reqwest::dns::Resolve`] for [`DnsResolver`].
    //!
    //! Wrapped in a newtype to not expose this in the public iroh API.

    use std::{net::SocketAddr, time::Duration};

    use iroh_dns::dns::DnsResolver;

    const DNS_TIMEOUT: Duration = Duration::from_secs(3);

    pub(super) struct ReqwestDnsResolver(pub(super) DnsResolver);

    impl reqwest::dns::Resolve for ReqwestDnsResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let this = self.0.clone();
            let name = name.as_str().to_string();
            Box::pin(async move {
                let res = this.lookup_ipv4_ipv6(name, DNS_TIMEOUT).await;
                match res {
                    Ok(addrs) => {
                        let addrs: reqwest::dns::Addrs =
                            Box::new(addrs.map(|addr| SocketAddr::new(addr, 0)));
                        Ok(addrs)
                    }
                    Err(err) => {
                        let err: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
                        Err(err)
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;

    use n0_future::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_maybefuture_poll_after_use() {
        let fut = async move { "hello" };
        let mut maybe_fut = pin!(MaybeFuture::Some(fut));
        let res = (&mut maybe_fut).await;

        assert_eq!(res, "hello");

        // Now poll again
        let res = tokio::time::timeout(Duration::from_millis(10), maybe_fut).await;
        assert!(res.is_err());
    }
}
