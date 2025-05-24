use std::{fmt, sync::Arc};

use async_trait::async_trait;
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
        MessageRequest, UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, RecordType},
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
};
use n0_snafu::{Result, ResultExt};
use snafu::whatever;
use tracing::{debug, trace};

use crate::{
    store::ZoneStore,
    util::{record_set_append_origin, PublicKeyBytes},
};

#[derive(derive_more::Debug)]
pub struct NodeAuthority {
    serial: u32,
    origins: Vec<Name>,
    #[debug("InMemoryAuthority")]
    static_authority: InMemoryAuthority,
    zones: ZoneStore,
    // TODO: This is used by Authority::origin
    // Find out what exactly this is used for - we don't have a primary origin.
    first_origin: LowerName,
}

impl NodeAuthority {
    pub fn new(
        zones: ZoneStore,
        static_authority: InMemoryAuthority,
        origins: Vec<Name>,
        serial: u32,
    ) -> Result<Self> {
        if origins.is_empty() {
            whatever!("at least one origin is required");
        }
        let first_origin = LowerName::from(&origins[0]);
        Ok(Self {
            static_authority,
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
impl Authority for NodeAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.first_origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        debug!(name=%name, "lookup in node authority");
        match record_type {
            RecordType::SOA | RecordType::NS => {
                self.static_authority
                    .lookup(name, record_type, lookup_options)
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
                    self.static_authority
                        .lookup(name, record_type, lookup_options)
                        .await
                }
            },
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        debug!("search in node authority for {}", request_info.query);
        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();
        match record_type {
            RecordType::SOA => {
                self.static_authority
                    .lookup(self.origin(), record_type, lookup_options)
                    .await
            }
            RecordType::AXFR => {
                LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::Refused)))
            }
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
        }
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
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
            whatever!("not a valid pkarr name: missing pubkey");
        }
        trace!("parse {origin}");
        let labels = name.iter().rev();
        let mut labels_without_origin = labels.skip(origin.num_labels() as usize);
        let pkey_label = labels_without_origin.next().expect("length checked above");
        let pkey_str = std::str::from_utf8(pkey_label).e()?;
        let pkey =
            PublicKeyBytes::from_z32(pkey_str).context("not a valid pkarr name: invalid pubkey")?;
        let remaining_name = Name::from_labels(labels_without_origin.rev()).e()?;
        return Ok((remaining_name, pkey, origin.clone()));
    }
    whatever!("name does not match any allowed origin");
}

fn err_refused(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (refused): {e:?}");
    LookupError::from(ResponseCode::Refused)
}
fn err_nx_domain(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (nxdomain): {e:?}");
    LookupError::from(ResponseCode::NXDomain)
}
