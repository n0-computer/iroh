use std::{fmt, sync::Arc};

use async_trait::async_trait;
use hickory_server::{
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, RecordType, TSigResponseContext},
    },
    server::{Request, RequestInfo},
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
        ZoneHandler, ZoneType,
    },
};
use n0_error::{Result, StackResultExt, StdResultExt, bail_any};
use tracing::{debug, trace};

use crate::{
    store::ZoneStore,
    util::{PublicKeyBytes, record_set_append_origin},
};

#[derive(derive_more::Debug)]
pub struct NodeZoneHandler {
    serial: u32,
    origins: Vec<Name>,
    #[debug("InMemoryZoneHandler")]
    static_zone_handler: InMemoryZoneHandler,
    zones: ZoneStore,
    // TODO: This is used by ZoneHandler::origin
    // Find out what exactly this is used for - we don't have a primary origin.
    first_origin: LowerName,
}

impl NodeZoneHandler {
    pub fn new(
        zones: ZoneStore,
        static_zone_handler: InMemoryZoneHandler,
        origins: Vec<Name>,
        serial: u32,
    ) -> Result<Self> {
        if origins.is_empty() {
            bail_any!("at least one origin is required");
        }
        let first_origin = LowerName::from(&origins[0]);
        Ok(Self {
            static_zone_handler,
            origins,
            serial,
            zones,
            first_origin,
        })
    }

    pub fn origins(&self) -> impl Iterator<Item = &Name> {
        self.origins.iter()
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    async fn resolve_pkarr(
        &self,
        name: Name,
        pubkey: PublicKeyBytes,
        origin: Name,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<AuthLookup, LookupError> {
        debug!(%origin, %pubkey, %name, "resolve in pkarr zones");
        match self
            .zones
            .resolve(&pubkey, &name, record_type)
            .await
            .map_err(err_refused)?
        {
            Some(pkarr_set) => {
                debug!(%origin, %pubkey, %name, "found {} records in pkarr zone", pkarr_set.records_without_rrsigs().count());
                let new_origin =
                    Name::parse(&pubkey.to_z32(), Some(&origin)).map_err(err_refused)?;
                let record_set = record_set_append_origin(&pkarr_set, &new_origin, self.serial())
                    .map_err(err_refused)?;
                let records = LookupRecords::new(lookup_options, Arc::new(record_set));
                let answers = AuthLookup::answers(records, None);
                Ok(answers)
            }
            None => Err(err_nx_domain("not found")),
        }
    }
}

#[async_trait]
impl ZoneHandler for NodeZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.first_origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        debug!(name=%name, "lookup in node authority");
        match record_type {
            RecordType::SOA | RecordType::NS => {
                self.static_zone_handler
                    .lookup(name, record_type, request_info, lookup_options)
                    .await
            }
            _ => match parse_name_as_pkarr_with_origin(name, &self.origins) {
                Ok((name, pubkey, origin)) => {
                    let res = self
                        .resolve_pkarr(name, pubkey, origin, record_type, lookup_options)
                        .await;
                    LookupControlFlow::Continue(res)
                }
                Err(err) => {
                    debug!(%name, failed_with=%err, "not a pkarr name, resolve in static authority");
                    self.static_zone_handler
                        .lookup(name, record_type, request_info, lookup_options)
                        .await
                }
            },
        }
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(err) => return (LookupControlFlow::Continue(Err(err)), None),
        };
        debug!("search in node authority for {}", request_info.query);
        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();
        let result = match record_type {
            RecordType::SOA => {
                self.static_zone_handler
                    .lookup(
                        self.origin(),
                        record_type,
                        Some(&request_info),
                        lookup_options,
                    )
                    .await
            }
            RecordType::AXFR => {
                LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)))
            }
            _ => {
                self.lookup(
                    lookup_name,
                    record_type,
                    Some(&request_info),
                    lookup_options,
                )
                .await
            }
        };
        (result, None)
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Skip
    }
}

fn parse_name_as_pkarr_with_origin(
    name: impl Into<Name>,
    allowed_origins: &[Name],
) -> Result<(Name, PublicKeyBytes, Name)> {
    let name = name.into();
    trace!("resolve {name}");
    for origin in allowed_origins.iter() {
        trace!("try {origin}");
        if !origin.zone_of(&name) {
            continue;
        }
        if name.num_labels() < origin.num_labels() + 1 {
            bail_any!("not a valid pkarr name: missing pubkey");
        }
        trace!("parse {origin}");
        let labels = name.iter().rev();
        let mut labels_without_origin = labels.skip(origin.num_labels() as usize);
        let pkey_label = labels_without_origin.next().expect("length checked above");
        let pkey_str = std::str::from_utf8(pkey_label).anyerr()?;
        let pkey =
            PublicKeyBytes::from_z32(pkey_str).context("not a valid pkarr name: invalid pubkey")?;
        let remaining_name = Name::from_labels(labels_without_origin.rev()).anyerr()?;
        return Ok((remaining_name, pkey, origin.clone()));
    }
    bail_any!("name does not match any allowed origin");
}

fn err_refused(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (refused): {e:?}");
    LookupError::from(ResponseCode::Refused)
}
fn err_nx_domain(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (nxdomain): {e:?}");
    LookupError::from(ResponseCode::NXDomain)
}
