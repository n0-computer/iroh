//! Utilities useful across different store impls.

use crate::SignedEntry;

use super::{AuthorFilter, KeyFilter, Query, QueryKind, SortBy};

/// A helper for stores that have by-author and by-key indexes for records.
#[derive(Debug)]
pub enum IndexKind {
    AuthorKey {
        range: AuthorFilter,
        filter: KeyFilter,
    },
    KeyAuthor {
        range: KeyFilter,
        filter: AuthorFilter,
        latest_per_key: bool,
    },
}

impl From<&Query> for IndexKind {
    fn from(query: &Query) -> Self {
        match &query.kind {
            QueryKind::Flat(details) => match (&query.filter_author, details.sort_by) {
                (AuthorFilter::Any, SortBy::KeyAuthor) => IndexKind::KeyAuthor {
                    range: query.filter_key.clone(),
                    filter: AuthorFilter::Any,
                    latest_per_key: false,
                },
                _ => IndexKind::AuthorKey {
                    range: query.filter_author.clone(),
                    filter: query.filter_key.clone(),
                },
            },
            QueryKind::SingleLatestPerKey(_) => IndexKind::KeyAuthor {
                range: query.filter_key.clone(),
                filter: query.filter_author.clone(),
                latest_per_key: true,
            },
        }
    }
}

#[derive(Debug, Default)]
pub struct LatestPerKeySelector(Option<SignedEntry>);

pub enum SelectorRes {
    Finished,
    Continue,
    Some(SignedEntry),
}

impl LatestPerKeySelector {
    pub fn push(&mut self, entry: Option<SignedEntry>) -> SelectorRes {
        let Some(entry) = entry else {
            return match self.0.take() {
                Some(entry) => SelectorRes::Some(entry),
                None => SelectorRes::Finished,
            };
        };
        match self.0.take() {
            None => {
                self.0 = Some(entry);
                SelectorRes::Continue
            }
            Some(last) if last.key() == entry.key() => {
                if entry.timestamp() > last.timestamp() {
                    self.0 = Some(entry);
                } else {
                    self.0 = Some(last);
                }
                SelectorRes::Continue
            }
            Some(last) => {
                self.0 = Some(entry);
                SelectorRes::Some(last)
            }
        }
    }
}
