use async_stream::stream;
use futures::Stream;
use tonic::transport::channel::Channel;
use tonic_health::proto::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
    HealthCheckResponse,
};

#[tracing::instrument(skip(health_client))]
pub async fn check(health_client: HealthClient<Channel>, service: String) -> ServiceStatus {
    let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest { service });
    let res = health_client.clone().check(req).await;
    match res {
        Ok(res) => res.into_inner().into(),
        Err(s) => ServiceStatus::Down(s),
    }
}

#[tracing::instrument(skip(health_client))]
pub async fn watch(
    health_client: HealthClient<Channel>,
    service: String,
) -> impl Stream<Item = ServiceStatus> {
    stream! {
        loop {
            let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest { service: service.clone() });
            let res = health_client.clone().watch(req).await;
            match res {
                Ok(stream) => {
                    let mut stream = stream.into_inner();
                    // loop over the stream, breaking if we get an error or stop receiving messages
                    loop {
                        match stream.message().await {
                            Ok(Some(message)) => yield message.into(),
                            Ok(None) => {
                                yield ServiceStatus::Down(tonic::Status::new(tonic::Code::Unavailable, format!("No more health messages from service `{}`", service)));
                                break;
                            }
                            Err(status) => {
                                yield ServiceStatus::Down(status);
                                break;
                            }
                        }
                    }
                },
                Err(status) => yield ServiceStatus::Down(status)
            }
            /// wait before attempting to start a watch stream again
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        };
    }
}

impl std::convert::From<HealthCheckResponse> for ServiceStatus {
    fn from(h: HealthCheckResponse) -> Self {
        match h.status() {
            ServingStatus::Unknown => ServiceStatus::Unknown,
            ServingStatus::Serving => ServiceStatus::Serving,
            ServingStatus::NotServing => ServiceStatus::NotServing,
            ServingStatus::ServiceUnknown => ServiceStatus::ServiceUnknown,
        }
    }
}

#[derive(Debug)]
pub enum ServiceStatus {
    ///  Indicates rpc server is in an unknown state
    Unknown,
    ///  Indicates service is being created but isn't ready to serve
    Pending,
    /// Indicates service is serving data
    Serving,
    /// Indicates service is not serving data, but the rpc server is not down
    NotServing,
    /// Indicates that the requested service is unknown
    ServiceUnknown,
    /// Indicates that the service is down. This ServiceStatus is assigned when
    /// a `check` or `watch` call has returned an error with `tonic::Status`
    Down(tonic::Status),
}

impl std::clone::Clone for ServiceStatus {
    fn clone(&self) -> Self {
        match self {
            ServiceStatus::Down(status) => {
                ServiceStatus::Down(tonic::Status::new(status.code(), status.message()))
            }
            ServiceStatus::Unknown => ServiceStatus::Unknown,
            ServiceStatus::Pending => ServiceStatus::Pending,
            ServiceStatus::Serving => ServiceStatus::Serving,
            ServiceStatus::NotServing => ServiceStatus::NotServing,
            ServiceStatus::ServiceUnknown => ServiceStatus::ServiceUnknown,
        }
    }
}

// struct WatchStreamResult(std::result::Result<tonic::Response<HealthCheckResponse>, tonic::Status>);
// struct ServiceStatusResult(Result<ServiceStatus>);

// impl std::convert::From<WatchStreamResult> for ServiceStatusResult {
//     fn from(res: WatchStreamResult) -> Self {
//         match res.0 {
//             Ok(res) => match res.into_inner().status() {
//                 tonic_health::proto::health_check_response::ServingStatus::Unknown => {
//                     ServiceStatusResult(Ok(ServiceStatus::Unknown))
//                 }
//                 tonic_health::proto::health_check_response::ServingStatus::Serving => {
//                     ServiceStatusResult(Ok(ServiceStatus::Serving))
//                 }
//                 tonic_health::proto::health_check_response::ServingStatus::NotServing => {
//                     ServiceStatusResult(Ok(ServiceStatus::NotServing))
//                 }
//                 tonic_health::proto::health_check_response::ServingStatus::ServiceUnknown => {
//                     ServiceStatusResult(Err(anyhow!("service unknown")))
//                 }
//             },
//             Err(s) => match s.code() {
//                 tonic::Code::Unavailable => ServiceStatusResult(Ok(ServiceStatus::Down)),
//                 _ => ServiceStatusResult(Err(anyhow!("unexpected rpc status {:?}", s))),
//             },
//         }
//     }
// }
