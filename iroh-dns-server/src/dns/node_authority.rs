use std::{fmt, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::ResponseCode,
    rr::{LowerName, Name, RecordType},
};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest,
        UpdateResult, ZoneType,
    },
    server::RequestInfo,
    store::in_memory::InMemoryAuthority,
};

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
        ensure!(!origins.is_empty(), "at least one origin is required");
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
    ) -> Result<Self::Lookup, LookupError> {
        debug!(name=%name, "lookup in node authority");
        match record_type {
            RecordType::SOA | RecordType::NS => {
                self.static_authority
                    .lookup(name, record_type, lookup_options)
                    .await
            }
            _ => match parse_name_as_pkarr_with_origin(name, &self.origins) {
                Err(err) => {
                    trace!(%name, ?err, "name is not a pkarr zone");
                    debug!("resolve static: name {name}");
                    self.static_authority
                        .lookup(name, record_type, lookup_options)
                        .await
                }
                Ok((name, pubkey, origin)) => {
                    debug!(%origin, "resolve pkarr: {name} {pubkey}");
                    match self
                        .zones
                        .resolve(&pubkey, &name, record_type)
                        .await
                        .map_err(err_refused)?
                    {
                        Some(pkarr_set) => {
                            let new_origin = Name::parse(&pubkey.to_z32(), Some(&origin))
                                .map_err(err_refused)?;
                            let record_set =
                                record_set_append_origin(&pkarr_set, &new_origin, self.serial())
                                    .map_err(err_refused)?;
                            let records = LookupRecords::new(lookup_options, Arc::new(record_set));
                            let answers = AuthLookup::answers(records, None);
                            Ok(answers)
                        }
                        None => Err(err_nx_domain("not found")),
                    }
                }
            },
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        debug!("searching NodeAuthority for: {}", request_info.query);
        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();
        match record_type {
            RecordType::SOA => {
                self.static_authority
                    .lookup(self.origin(), record_type, lookup_options)
                    .await
            }
            RecordType::AXFR => Err(LookupError::from(ResponseCode::Refused)),
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
        }
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(AuthLookup::default())
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
            bail!("not a valid pkarr name: missing pubkey");
        }
        trace!("parse {origin}");
        let labels = name.iter().rev();
        let mut labels_without_origin = labels.skip(origin.num_labels() as usize);
        let pkey_label = labels_without_origin.next().expect("length checked above");
        let pkey_str = std::str::from_utf8(pkey_label)?;
        let pkey = PublicKeyBytes::from_z32(pkey_str).context("not a valid pkarr name: invalid pubkey")?;
        let remaining_name = Name::from_labels(labels_without_origin.rev())?;
        return Ok((remaining_name, pkey, origin.clone()));
    }
    bail!("name does not match any allowed origin");
}

fn err_refused(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (refused): {e:?}");
    LookupError::from(ResponseCode::Refused)
}
fn err_nx_domain(e: impl fmt::Debug) -> LookupError {
    trace!("lookup failed (nxdomain): {e:?}");
    LookupError::from(ResponseCode::NXDomain)
}
