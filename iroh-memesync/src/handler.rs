use std::{
    collections::VecDeque,
    fmt::Debug,
    task::Context,
    task::Poll,
    time::{Duration, Instant},
};

use asynchronous_codec::Framed;
use bytes::Bytes;
use cid::Cid;
use futures::stream::{BoxStream, SelectAll};
use futures::{SinkExt, Stream, StreamExt};
use libp2p::swarm::handler::{
    ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr,
    DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound, KeepAlive,
    SubstreamProtocol,
};
use libp2p::swarm::NegotiatedSubstream;
use tracing::{trace, warn};

use crate::store::{GetResult, Store};
use crate::{
    protocol::{MemesyncCodec, MemesyncProtocol},
    QueryId,
};
use crate::{
    Error, Message, Path, Recursion, RecursionDirection, Request, Response, ResponseError,
    ResponseOk,
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum HandlerEvent {
    Upgrade,
    ResponseProgress {
        id: QueryId,
        index: u32,
        last: bool,
        data: Bytes,
        links: Vec<(Option<String>, Cid)>,
        cid: Cid,
    },
    /// Received a response, but it was invalid.
    ResponseError {
        id: QueryId,
    },
    RequestFailed {
        request: Request,
        err: HandlerError,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum HandlerError {
    /// The maximum number of inbound substreams created has been exceeded.
    #[error("max inbound substreams")]
    MaxInboundSubstreams,
    /// The maximum number of outbound substreams created has been exceeded.
    #[error("max outbound substreams")]
    MaxOutboundSubstreams,
    /// The message exceeds the maximum transmission size.
    #[error("max transmission size")]
    MaxTransmissionSize,
    /// Protocol negotiation timeout.
    #[error("negotiation timeout")]
    NegotiationTimeout,
    #[error("empty inbound message")]
    EmptyInbound,
    #[error("invalid inbound messae")]
    InvalidInbound,
    /// IO error.
    #[error("io {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] Error),
}

pub struct Handler<S: Store> {
    /// If `Some`, something bad happened and we should shut down the handler with an error.
    pending_error: Option<ConnectionHandlerUpgrErr<HandlerError>>,
    /// Queue of events to produce in `poll()`.
    events_out: Vec<HandlerEvent>,
    /// Queue of outbound substreams to open.
    dial_queue: Vec<Request>,
    /// Current number of concurrent outbound substreams being opened.
    dial_negotiated: u32,
    /// Value to return from `connection_keep_alive`.
    keep_alive: KeepAlive,
    /// The configuration container for the handler
    config: HandlerConfig,

    outbound_substreams: SelectAll<BoxStream<'static, ConnHandlerEvent>>,
    inbound_substreams: SelectAll<BoxStream<'static, ConnHandlerEvent>>,

    store: S,
}

impl<S: Store> Handler<S> {
    /// Creates a `Handler`.
    pub fn new(store: S, config: HandlerConfig) -> Self {
        Handler {
            pending_error: None,
            events_out: Default::default(),
            dial_queue: Default::default(),
            dial_negotiated: 0,
            keep_alive: KeepAlive::Yes,
            config,
            inbound_substreams: Default::default(),
            outbound_substreams: Default::default(),
            store,
        }
    }

    /// Returns the number of pending requests.
    pub fn pending_requests(&self) -> u32 {
        self.dial_negotiated + self.dial_queue.len() as u32
    }

    /// Opens an outbound substream with `upgrade`.
    pub fn send_request(&mut self, upgrade: Request) {
        self.keep_alive = KeepAlive::Yes;
        self.dial_queue.push(upgrade);
    }
}

type ConnHandlerEvent = ConnectionHandlerEvent<
    MemesyncProtocol,
    Request,
    HandlerEvent,
    ConnectionHandlerUpgrErr<HandlerError>,
>;

impl<S: Store> ConnectionHandler for Handler<S> {
    type InEvent = Request;
    type OutEvent = HandlerEvent;
    type Error = ConnectionHandlerUpgrErr<HandlerError>;
    type InboundProtocol = MemesyncProtocol;
    type OutboundProtocol = MemesyncProtocol;
    type OutboundOpenInfo = Request;
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(MemesyncProtocol, ())
    }

    fn on_behaviour_event(&mut self, event: Self::InEvent) {
        self.send_request(event);
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnHandlerEvent> {
        if let Some(err) = self.pending_error.take() {
            return Poll::Ready(ConnectionHandlerEvent::Close(err));
        }

        if !self.events_out.is_empty() {
            return Poll::Ready(ConnectionHandlerEvent::Custom(self.events_out.remove(0)));
        } else {
            self.events_out.shrink_to_fit();
        }

        if !self.dial_queue.is_empty() {
            if self.dial_negotiated < self.config.max_dial_negotiated {
                self.dial_negotiated += 1;
                let upgrade = self.dial_queue.remove(0);
                return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                    protocol: SubstreamProtocol::new(MemesyncProtocol, upgrade)
                        .with_timeout(self.config.outbound_substream_timeout),
                });
            }
        } else {
            self.dial_queue.shrink_to_fit();

            if self.dial_negotiated == 0 && self.keep_alive.is_yes() {
                self.keep_alive = KeepAlive::Until(Instant::now() + self.config.keep_alive_timeout);
            }
        }

        if let Poll::Ready(Some(event)) = self.outbound_substreams.poll_next_unpin(cx) {
            return Poll::Ready(event);
        }

        if let Poll::Ready(Some(event)) = self.inbound_substreams.poll_next_unpin(cx) {
            return Poll::Ready(event);
        }

        if self.outbound_substreams.is_empty() && self.inbound_substreams.is_empty() {
            // We destroyed all substreams in this function.
            self.keep_alive = KeepAlive::Until(Instant::now() + self.config.keep_alive_timeout);
        } else {
            self.keep_alive = KeepAlive::Yes;
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: (stream, req),
                ..
            }) => {
                // If we're shutting down the connection for inactivity, reset the timeout.
                if !self.keep_alive.is_yes() {
                    self.keep_alive =
                        KeepAlive::Until(Instant::now() + self.config.keep_alive_timeout);
                }

                self.inbound_substreams.push(create_inbound_stream(
                    req,
                    stream,
                    self.store.clone(),
                ));
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                info: initial_message,
            }) => {
                self.dial_negotiated -= 1;
                self.outbound_substreams
                    .push(create_outbound_stream(initial_message, stream));
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, .. }) => {
                if self.pending_error.is_none() {
                    // TODO: handle multiple errors
                    self.pending_error = Some(error);
                }
            }
            ConnectionEvent::AddressChange(_) | ConnectionEvent::ListenUpgradeError(_) => {}
        }
    }
}

fn create_outbound_stream(
    req: Request,
    mut stream: Framed<NegotiatedSubstream, MemesyncCodec>,
) -> BoxStream<'static, ConnHandlerEvent> {
    trace!("new outbound stream: {:?}", req);

    async_stream::stream! {
        let id = req.id;
        let query = req.query.clone();

        // sending message
        if let Err(err) = stream.send(Message::Request(req)).await {
            warn!("failed to send message: {:?}", err);
            return;
        }

        // Track CIDs, to verify the sender is sending the expected data.
        let mut cids = VecDeque::new();
        cids.push_back((None, query.path.root));

        // Track the tail of the query that is left to resolve.
        let mut tail_left: VecDeque <_>  = query.path.tail.iter().cloned().collect();

        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Request(_) => {
                    warn!("expected response, received request");
                    // TODO: send error
                    break;
                }
                Message::Response(resp) => {
                    trace!("response received: {:?}", resp);
                    if resp.id != id {
                        warn!("invalid query id received: {:?} != {:?}", resp.id, id);
                        yield ConnectionHandlerEvent::Custom(HandlerEvent::ResponseError { id });
                        break;
                    }
                    // Verify incoming data
                    if cids.is_empty() {
                        warn!("received more responses than expected");
                        yield ConnectionHandlerEvent::Custom(HandlerEvent::ResponseError { id });
                        break;
                    }

                    // If the response is valid
                    match resp.response {
                        Ok(res_ok) => {
                            let bytes = res_ok.data.clone();
                            let (name, cid) = cids.pop_front().unwrap();

                            // 1. match data against expected cid
                            trace!("checking link {:?}", name);
                            if !iroh_util::verify_hash(&cid, &bytes).unwrap_or_default() {
                                warn!("received invalid block: {:?} ({})", name, cid);
                                yield ConnectionHandlerEvent::Custom(HandlerEvent::ResponseError { id });
                                break;
                            }

                            // 2. parse links and remember them, to verify the next blocks
                            let links = tokio::task::spawn_blocking(move || {
                                iroh_util::parse_links_with_names(&cid, &bytes).unwrap_or_default()
                            }).await.unwrap_or_default();

                            if tail_left.is_empty() {
                                match &query.recursion {
                                    Recursion::Some { direction, .. } => {
                                        match direction {
                                            RecursionDirection::BreadthFirst => {
                                                for (name, link) in &links {
                                                    cids.push_back((name.clone(), *link));
                                                }
                                            }
                                            RecursionDirection::DepthFirst => {
                                                // TODO
                                            }
                                        }
                                    }
                                    Recursion::None => {
                                        // Nothing to do
                                    }
                                }
                            } else {
                                // next link should be the tail link
                                let name = tail_left.pop_front();
                                if let Some((_, next_link)) = links.iter().find(|(n, _)| {
                                    name.is_some() && n.as_ref() == name.as_ref()
                                }) {
                                    cids.push_back((name.clone(), *next_link));
                                } else {
                                    warn!("query invalid");
                                    yield ConnectionHandlerEvent::Custom(HandlerEvent::ResponseError { id });
                                    break;
                                }
                            }

                            // Yield the response.
                            yield ConnectionHandlerEvent::Custom(HandlerEvent::ResponseProgress {
                                id: resp.id,
                                index: res_ok.index,
                                last: res_ok.last,
                                data: res_ok.data,
                                links,
                                cid,
                            });

                            if res_ok.last {
                                break;
                            }
                        }
                        Err(err) => {
                            warn!("response error: {:?}", err);
                            // Yield the response.
                            yield ConnectionHandlerEvent::Custom(HandlerEvent::ResponseError { id: resp.id });
                            break;
                        }
                    }
                }
            }
        }

        // All responses received, close the stream.
        if let Err(err) = stream.flush().await {
            warn!("failed to flush stream: {:?}", err);
        }
        if let Err(err) = stream.close().await {
            warn!("failed to close stream: {:?}", err);
        }
    }
    .boxed()
}

fn create_inbound_stream<S: Store>(
    req: Request,
    mut stream: Framed<NegotiatedSubstream, MemesyncCodec>,
    store: S,
) -> BoxStream<'static, ConnHandlerEvent> {
    trace!("new inbound stream: {:?}", req);
    async_stream::stream! {
        let responses = create_response_stream(req.clone(), store);
        tokio::pin!(responses);
        while let Some(response) = responses.next().await {
            trace!("response created, sending: {:?}", response);

            if let Err(err) = stream.feed(Message::Response(response)).await {
                warn!("failed to write item: {:?}", err);
                yield ConnectionHandlerEvent::Custom(
                    HandlerEvent::RequestFailed { request: req, err }
                );
                break;
            }
        }

        // All responses sent, close the stream
        if let Err(err) = stream.flush().await {
            warn!("failed to flush stream: {:?}", err);
        }
        if let Err(err) = stream.close().await {
            warn!("failed to close stream: {:?}", err);
        }
    }
    .boxed()
}

fn create_response_stream<S: Store>(req: Request, store: S) -> impl Stream<Item = Response> {
    // Trigger data loading
    async_stream::stream! {
        let Request { query, id } = req;
        let mut index = 0;
        let root = query.path.root;
        let mut tail = query.path.tail;
        let mut current_links = Vec::new();

        trace!("loading root: {}", root);
        let response = match store.get(root).await {
            Ok(Some(GetResult { data, links })) => {
                let i = index;
                index += 1;
                let is_last = tail.is_empty() && (query.recursion == Recursion::None || links.is_empty());
                current_links = links;

                Ok(ResponseOk {
                    index: i,
                    last: is_last,
                    data,
                })
            }
            Ok(None) => Err(ResponseError::NotFound(
                crate::Path::from(root)
            )),
            Err(err) => {
                warn!("failed to retrieve the data: {:?}", err);
                Err(ResponseError::Other)
            }
        };


        let is_err = response.is_err();
        yield Response {
            id,
            response
        };

        if is_err {
            return;
        }

        let mut current_path = Path {
            root,
            tail: vec![],
        };

        // resolve the tail
        trace!("resolving tail: {:?}", tail);
        while let Some(part) = tail.pop() {
            trace!("loading tail piece: {:?}", part);
            let response =  if let Some((_, cid)) = current_links.iter().find(|(name, _)| { name.as_ref() == Some(&part) }) {
                trace!("part: {} ({})", part, cid);
                current_path.tail.push(part);

                match store.get(*cid).await {
                    Ok(Some(GetResult { data, links })) => {
                        let i = index;
                        index += 1;
                        current_links = links;
                        let is_last = tail.is_empty() && query.recursion == Recursion::None;

                        Ok(ResponseOk {
                            index: i,
                            last: is_last,
                            data,
                        })
                    }
                    Ok(None) => Err(ResponseError::NotFound(
                        current_path.clone()
                    )),
                    Err(err) => {
                        warn!("failed to retrieve the data: {:?}", err);
                        Err(ResponseError::Other)
                    }
                }
            } else {
                Err(ResponseError::InvalidLink { valid_up_to: index - 1 })
            };

            let is_err = response.is_err();

            yield Response {
                id,
                response
            };

            if is_err {
                // this query failed, break this loop
                break;
            }
        }

        // Resolve recursion
        if let Recursion::Some { depth, direction} = query.recursion {
            trace!("resolving recursion depth: {}: {:?}", depth, direction);
            match direction {
                RecursionDirection::BreadthFirst => {
                    let mut next_links = current_links;
                    for current_depth in 0..depth {
                        if next_links.is_empty() {
                            break;
                        }

                        let current_links = std::mem::take(&mut next_links);
                        let num_links = current_links.len();
                        trace!("resolving {}/{} depth with {} links", current_depth, depth, num_links);

                        for (link_index, (name, cid)) in current_links.into_iter().enumerate() {
                            trace!("resolving link {:?} ({})", name, cid);
                            // TODO: fix current_path
                            if let Some(name) = name {
                                current_path.tail.push(name);
                            } else {
                                current_path.tail.push(cid.into());
                            }
                            let mut is_last = current_depth == depth - 1 && link_index == num_links - 1;
                            let response = match store.get(cid).await {
                                Ok(Some(GetResult { data, links })) => {
                                    let i = index;
                                    index += 1;
                                    next_links.extend(links);
                                    if link_index == num_links - 1 && next_links.is_empty() {
                                        is_last = true;
                                    }

                                    Ok(ResponseOk {
                                        index: i,
                                        last: is_last,
                                        data,
                                    })
                                }
                                Ok(None) => Err(ResponseError::NotFound(current_path.clone())),
                                Err(err) => {
                                    warn!("failed to retrieve the data: {:?}", err);
                                    Err(ResponseError::Other)
                                }
                            };
                            let is_err = response.is_err();
                            yield Response {
                                id,
                                response,
                            };
                            if is_err || is_last {
                                break;
                            }
                        }
                    }
                }
                RecursionDirection::DepthFirst => {
                    // TODO:
                    warn!("TODO: depth first");
                    yield Response {
                        id,
                        response: Err(ResponseError::Other),
                    }
                }
            }
        }
    }
}

/// Configuration parameters for the `Handler`
#[derive(Debug)]
pub struct HandlerConfig {
    /// Keep-alive timeout for idle connections.
    pub keep_alive_timeout: Duration,
    /// Timeout for outbound substream upgrades.
    pub outbound_substream_timeout: Duration,
    /// Maximum number of concurrent outbound substreams being opened.
    pub max_dial_negotiated: u32,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        HandlerConfig {
            keep_alive_timeout: Duration::from_secs(10),
            outbound_substream_timeout: Duration::from_secs(10),
            max_dial_negotiated: 8,
        }
    }
}
