use libp2p::NetworkBehaviour;

use crate::request_response::{
    new_request_response_behaviour, RequestResponse, RequestResponseEvent,
};
use crate::streaming::{new_streaming_behaviour, Streaming, StreamingEvent};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "CoreEvent")]
pub struct CoreBehaviour {
    pub request_response: RequestResponse,
    pub streaming: Streaming,
}

impl CoreBehaviour {
    pub fn new() -> Self {
        CoreBehaviour {
            request_response: new_request_response_behaviour(),
            streaming: new_streaming_behaviour(),
        }
    }
}

impl Default for CoreBehaviour {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum CoreEvent {
    RequestResponse(RequestResponseEvent),
    Streaming(StreamingEvent),
}

impl From<RequestResponseEvent> for CoreEvent {
    fn from(event: RequestResponseEvent) -> Self {
        CoreEvent::RequestResponse(event)
    }
}

impl From<StreamingEvent> for CoreEvent {
    fn from(event: StreamingEvent) -> Self {
        CoreEvent::Streaming(event)
    }
}
