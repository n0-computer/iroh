use anyhow::Result;
use iroh_base::hash::Hash;

use crate::{
    store::{
        util::{IndexKind, LatestPerKeySelector, SelectorRes},
        AuthorFilter, KeyFilter, Query,
    },
    AuthorId, NamespaceId, SignedEntry,
};

use super::{
    bounds::{ByKeyBounds, RecordsBounds},
    ranges::{RecordsByKeyRange, RecordsRange},
    tables::ReadOnlyTables,
    RecordsValue,
};

/// A query iterator for entry queries.
#[derive(Debug)]
pub struct QueryIterator {
    range: QueryRange,
    query: Query,
    offset: u64,
    count: u64,
}

#[derive(Debug)]
enum QueryRange {
    AuthorKey {
        range: RecordsRange,
        key_filter: KeyFilter,
    },
    KeyAuthor {
        range: RecordsByKeyRange,
        author_filter: AuthorFilter,
        selector: Option<LatestPerKeySelector>,
    },
}

impl QueryIterator {
    pub fn new(tables: ReadOnlyTables, namespace: NamespaceId, query: Query) -> Result<Self> {
        let index_kind = IndexKind::from(&query);
        let range = match index_kind {
            IndexKind::AuthorKey { range, key_filter } => {
                let (bounds, filter) = match range {
                    // single author: both author and key are selected via the range. therefore
                    // set `filter` to `Any`.
                    AuthorFilter::Exact(author) => (
                        RecordsBounds::author_key(namespace, author, key_filter),
                        KeyFilter::Any,
                    ),
                    // no author set => full table scan with the provided key filter
                    AuthorFilter::Any => (RecordsBounds::namespace(namespace), key_filter),
                };
                let range = RecordsRange::with_bounds(&tables, bounds)?;
                QueryRange::AuthorKey {
                    range,
                    key_filter: filter,
                }
            }
            IndexKind::KeyAuthor {
                range,
                author_filter,
                latest_per_key,
            } => {
                let bounds = ByKeyBounds::new(namespace, &range);
                let range = RecordsByKeyRange::with_bounds(tables, bounds)?;
                let selector = latest_per_key.then(LatestPerKeySelector::default);
                QueryRange::KeyAuthor {
                    author_filter,
                    range,
                    selector,
                }
            }
        };

        Ok(QueryIterator {
            range,
            query,
            offset: 0,
            count: 0,
        })
    }
}

impl Iterator for QueryIterator {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Result<SignedEntry>> {
        // early-return if we reached the query limit.
        if let Some(limit) = self.query.limit() {
            if self.count >= limit {
                return None;
            }
        }
        loop {
            let next = match &mut self.range {
                QueryRange::AuthorKey { range, key_filter } => {
                    // get the next entry from the query range, filtered by the key and empty filters
                    range.next_filtered(&self.query.sort_direction, |(_ns, _author, key), value| {
                        key_filter.matches(key)
                            && (self.query.include_empty || !value_is_empty(&value))
                    })
                }

                QueryRange::KeyAuthor {
                    range,
                    author_filter,
                    selector,
                } => loop {
                    // get the next entry from the query range, filtered by the author filter
                    let next = range
                        .next_filtered(&self.query.sort_direction, |(_ns, _key, author)| {
                            author_filter.matches(&(AuthorId::from(author)))
                        });

                    // early-break if next contains Err
                    let next = match next.transpose() {
                        Err(err) => break Some(Err(err)),
                        Ok(next) => next,
                    };

                    // push the entry into the selector. if active, only the latest entry
                    // for each key will be emitted.
                    let next = match selector {
                        None => next,
                        Some(selector) => match selector.push(next) {
                            SelectorRes::Continue => continue,
                            SelectorRes::Finished => None,
                            SelectorRes::Some(res) => Some(res),
                        },
                    };

                    // skip the entry if empty and no empty entries requested
                    if !self.query.include_empty && matches!(&next, Some(e) if e.is_empty()) {
                        continue;
                    }

                    break next.map(Result::Ok);
                },
            };

            // skip the entry if we didn't get past the requested offset yet.
            if self.offset < self.query.offset() && matches!(next, Some(Ok(_))) {
                self.offset += 1;
                continue;
            }

            self.count += 1;
            return next;
        }
    }
}

fn value_is_empty(value: &RecordsValue) -> bool {
    let (_timestamp, _namespace_sig, _author_sig, _len, hash) = value;
    *hash == Hash::EMPTY.as_bytes()
}
