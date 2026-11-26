//! Answering queries for the configured origins.

use n0_error::{Result, StdResultExt, anyerr, bail_any, ensure_any};
use simple_dns::{
    CLASS, RCODE, ResourceRecord,
    rdata::{self, RData},
};
use tracing::debug;

use super::{
    DnsConfig,
    message::{
        DnsName, QCLASS_ANY, QCLASS_IN, QTYPE_ANY, QTYPE_AXFR, QTYPE_IXFR, Query, Response,
        record_type,
    },
};
use crate::{
    store::{ZoneLookup, ZoneStore},
    util::PublicKeyBytes,
};

const DEFAULT_NS_TTL: u32 = 60 * 60 * 12; // 12h
const DEFAULT_SOA_TTL: u32 = 60 * 60 * 24 * 14; // 14d
const DEFAULT_A_TTL: u32 = 60 * 60; // 1h

/// Authoritative data for the configured origins.
///
/// Each origin serves the same static records at its apex, and the pkarr zone of a public
/// key `<z32>` under `<z32>.<origin>`.
#[derive(derive_more::Debug)]
pub(super) struct Authority {
    /// Lowercased origins, in configuration order.
    origins: Vec<DnsName>,
    /// Records served at each origin apex. Their owner names are replaced on output.
    #[debug("{} records", apex_records.len())]
    apex_records: Vec<ResourceRecord<'static>>,
    /// SOA rdata, also used in the authority section of negative answers.
    #[debug(skip)]
    soa: rdata::SOA<'static>,
    zones: ZoneStore,
}

/// Where a query name falls within the configured origins.
enum Target<'a> {
    /// The apex of an origin.
    Apex(&'a DnsName),
    /// A name in the pkarr zone of `pubkey`, relative to that zone.
    Pkarr {
        origin: &'a DnsName,
        pubkey: PublicKeyBytes,
        name: DnsName,
    },
    /// A name below an origin that is not a pkarr zone.
    Unknown(&'a DnsName),
}

impl Authority {
    pub(super) fn new(zones: ZoneStore, config: &DnsConfig) -> Result<Self> {
        let origins = config
            .origins
            .iter()
            .map(|origin| DnsName::parse(origin).map(|name| name.to_ascii_lowercase()))
            .collect::<Result<Vec<_>>>()?;
        ensure_any!(!origins.is_empty(), "at least one origin is required");

        let soa = parse_soa(&config.default_soa)?;
        let root = DnsName::default().to_simple();
        let mut apex_records = vec![ResourceRecord::new(
            root.clone(),
            CLASS::IN,
            DEFAULT_SOA_TTL,
            RData::SOA(soa.clone()),
        )];
        if let Some(addr) = config.rr_a {
            apex_records.push(ResourceRecord::new(
                root.clone(),
                CLASS::IN,
                DEFAULT_A_TTL,
                RData::A(addr.into()),
            ));
        }
        if let Some(addr) = config.rr_aaaa {
            apex_records.push(ResourceRecord::new(
                root.clone(),
                CLASS::IN,
                DEFAULT_A_TTL,
                RData::AAAA(addr.into()),
            ));
        }
        if let Some(ns) = &config.rr_ns {
            let ns = DnsName::parse(ns)?.to_simple();
            apex_records.push(ResourceRecord::new(
                root,
                CLASS::IN,
                DEFAULT_NS_TTL,
                RData::NS(rdata::NS(ns)),
            ));
        }
        Ok(Self {
            origins,
            apex_records,
            soa,
            zones,
        })
    }

    /// Answers a query.
    pub(super) async fn answer(&self, query: &Query) -> Response {
        let question = &query.question;
        if !matches!(question.qclass, QCLASS_IN | QCLASS_ANY)
            || matches!(question.qtype, QTYPE_AXFR | QTYPE_IXFR)
        {
            return query.response(RCODE::Refused);
        }
        let lower = question.name.to_ascii_lowercase();
        let Some(target) = self.target(&lower) else {
            return query.response(RCODE::Refused);
        };
        let qtype = question.qtype;
        let (origin, lookup) = match target {
            Target::Apex(origin) => {
                let records = self
                    .apex_records
                    .iter()
                    .filter(|record| qtype == QTYPE_ANY || record_type(record) == qtype)
                    .cloned()
                    .collect();
                (origin, ZoneLookup::Records(records))
            }
            Target::Pkarr {
                origin,
                pubkey,
                name,
            } => match self.zones.resolve(&pubkey, &name, qtype).await {
                Ok(Some(lookup)) => (origin, lookup),
                Ok(None) => (origin, ZoneLookup::NxDomain),
                Err(err) => {
                    debug!(%pubkey, "zone lookup failed: {err:#}");
                    return query.response(RCODE::ServerFailure);
                }
            },
            Target::Unknown(origin) => (origin, ZoneLookup::NxDomain),
        };

        let (rcode, records) = match lookup {
            ZoneLookup::NxDomain => (RCODE::NameError, Vec::new()),
            ZoneLookup::Records(records) => (RCODE::NoError, records),
        };
        let mut response = query.response(rcode);
        response.authoritative = true;
        let owner = question.name.to_simple();
        response.answers = records
            .into_iter()
            .map(|mut record| {
                record.name = owner.clone();
                record
            })
            .collect();
        if response.answers.is_empty() {
            // RFC 2308: negative answers carry the SOA, with the TTL capped at its minimum.
            response.authority.push(ResourceRecord::new(
                origin.to_simple(),
                CLASS::IN,
                DEFAULT_SOA_TTL.min(self.soa.minimum),
                RData::SOA(self.soa.clone()),
            ));
        }
        response
    }

    /// Locates a lowercased name within the origins.
    ///
    /// The first origin in configuration order that contains the name wins.
    fn target(&self, name: &DnsName) -> Option<Target<'_>> {
        let (origin, prefix) = self
            .origins
            .iter()
            .find_map(|origin| Some((origin, name.strip_suffix(origin)?)))?;
        let Some((pubkey_label, rest)) = prefix.split_last() else {
            return Some(Target::Apex(origin));
        };
        let pubkey = std::str::from_utf8(pubkey_label)
            .ok()
            .and_then(|s| PublicKeyBytes::from_z32(s).ok());
        Some(match pubkey {
            Some(pubkey) => Target::Pkarr {
                origin,
                pubkey,
                name: DnsName::from_labels(rest.to_vec()).expect("prefix of a valid name"),
            },
            None => Target::Unknown(origin),
        })
    }
}

/// Parses SOA rdata in zone file format.
///
/// The format is `mname rname serial refresh retry expire minimum`. Names are treated as
/// absolute whether or not they end in a dot.
fn parse_soa(s: &str) -> Result<rdata::SOA<'static>> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let [mname, rname, serial, refresh, retry, expire, minimum] = parts[..] else {
        bail_any!("SOA must have 7 fields, got {}: {s}", parts.len());
    };
    let num = |field: &str| {
        field
            .parse::<u32>()
            .std_context("invalid number in SOA")
            .map_err(|err| anyerr!("{err:#}: {s}"))
    };
    let signed = |field: &str| -> Result<i32> {
        i32::try_from(num(field)?).map_err(|_| anyerr!("SOA timer out of range: {s}"))
    };
    Ok(rdata::SOA {
        mname: DnsName::parse(mname)?.to_simple(),
        rname: DnsName::parse(rname)?.to_simple(),
        serial: num(serial)?,
        refresh: signed(refresh)?,
        retry: signed(retry)?,
        expire: signed(expire)?,
        minimum: num(minimum)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soa_parsing() {
        let soa =
            parse_soa("dns1.irohdns.example hostmaster.irohdns.example 0 10800 3600 604800 3600")
                .unwrap();
        assert_eq!(
            DnsName::from_simple(&soa.mname).to_string(),
            "dns1.irohdns.example."
        );
        assert_eq!(soa.refresh, 10800);
        assert_eq!(soa.minimum, 3600);
        assert!(parse_soa("a b 1 2 3").is_err());
        assert!(parse_soa("a b 1 2 3 4 x").is_err());
    }
}
