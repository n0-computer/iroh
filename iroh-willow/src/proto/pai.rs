//! Primitives for [Private Area Intersection]
//!
//! * Uses ristretto255 and SHA512 for `hash_into_group`.
//!
//! TODO: Use edwards25519 with [RFC 9380] instead.
//!
//! [Private Area Intersection]: https://willowprotocol.org/specs/pai/index.html
//! [RFC 9380]: https://www.rfc-editor.org/rfc/rfc9380

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use ufotofu::sync::consumer::IntoVec;
use willow_encoding::sync::Encodable;

use crate::proto::{
    data_model::{NamespaceId, Path, SubspaceId},
    grouping::AreaSubspace,
};

type ReadCapability = super::meadowcap::McCapability;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PsiGroup(RistrettoPoint);

#[derive(Debug, thiserror::Error)]
#[error("Invalid Psi Group")]
pub struct InvalidPsiGroup;

impl PsiGroup {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidPsiGroup> {
        let compressed = CompressedRistretto(bytes);
        let uncompressed = compressed.decompress().ok_or(InvalidPsiGroup)?;
        Ok(Self(uncompressed))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.compress().0
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PsiScalar(Scalar);

#[derive(Debug)]
pub struct PaiScheme;

impl PaiScheme {
    pub fn hash_into_group(fragment: &Fragment) -> PsiGroup {
        let encoded = {
            let mut consumer = IntoVec::<u8>::new();
            fragment
                .encode(&mut consumer)
                .expect("encoding not to fail");
            consumer.into_vec()
        };
        let point = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&encoded);
        PsiGroup(point)
    }

    pub fn get_scalar() -> PsiScalar {
        PsiScalar(Scalar::random(&mut rand::thread_rng()))
    }

    pub fn scalar_mult(group: PsiGroup, scalar: PsiScalar) -> PsiGroup {
        PsiGroup(group.0 * scalar.0)
    }

    pub fn is_group_equal(a: &PsiGroup, b: &PsiGroup) -> bool {
        a == b
    }

    pub fn get_fragment_kit(cap: &ReadCapability) -> FragmentKit {
        let granted_area = cap.granted_area();
        let granted_namespace = cap.granted_namespace();
        let granted_path = granted_area.path().clone();

        match granted_area.subspace() {
            AreaSubspace::Any => FragmentKit::Complete(*granted_namespace, granted_path),
            AreaSubspace::Id(granted_subspace) => {
                FragmentKit::Selective(*granted_namespace, *granted_subspace, granted_path)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Fragment {
    Pair(FragmentPair),
    Triple(FragmentTriple),
}

impl Fragment {
    pub fn into_parts(self) -> (NamespaceId, AreaSubspace, Path) {
        match self {
            Fragment::Pair((namespace_id, path)) => (namespace_id, AreaSubspace::Any, path),
            Fragment::Triple((namespace_id, subspace_id, path)) => {
                (namespace_id, AreaSubspace::Id(subspace_id), path)
            }
        }
    }
}

pub type FragmentTriple = (NamespaceId, SubspaceId, Path);

pub type FragmentPair = (NamespaceId, Path);

#[derive(Debug, Clone, Copy)]
pub enum FragmentKind {
    Primary,
    Secondary,
}

impl FragmentKind {
    pub fn is_secondary(&self) -> bool {
        matches!(self, FragmentKind::Secondary)
    }
}

#[derive(Debug, Clone)]
pub enum FragmentSet {
    Complete(Vec<FragmentPair>),
    Selective {
        primary: Vec<FragmentTriple>,
        secondary: Vec<FragmentPair>,
    },
}

#[derive(Debug)]
pub enum FragmentKit {
    Complete(NamespaceId, Path),
    Selective(NamespaceId, SubspaceId, Path),
}

impl FragmentKit {
    pub fn into_fragment_set(self) -> FragmentSet {
        match self {
            FragmentKit::Complete(namespace_id, path) => {
                let pairs = path
                    .all_prefixes()
                    .map(|prefix| (namespace_id, prefix))
                    .collect();
                FragmentSet::Complete(pairs)
            }
            FragmentKit::Selective(namespace_id, subspace_id, path) => {
                let primary = path
                    .all_prefixes()
                    .map(|prefix| (namespace_id, subspace_id, prefix))
                    .collect();
                let secondary = path
                    .all_prefixes()
                    .map(|prefix| (namespace_id, prefix))
                    .collect();
                FragmentSet::Selective { primary, secondary }
            }
        }
    }
}

use syncify::syncify;
use syncify::syncify_replace;

#[syncify(encoding_sync)]
mod encoding {
    #[syncify_replace(use ufotofu::sync::BulkConsumer;)]
    use ufotofu::local_nb::BulkConsumer;

    #[syncify_replace(use willow_encoding::sync::Encodable;)]
    use willow_encoding::Encodable;

    use super::*;

    impl Encodable for Fragment {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            match self {
                Fragment::Pair((namespace_id, path)) => {
                    namespace_id.encode(consumer).await?;
                    path.encode(consumer).await?;
                }
                Fragment::Triple((namespace_id, subspace_id, path)) => {
                    namespace_id.encode(consumer).await?;
                    subspace_id.encode(consumer).await?;
                    path.encode(consumer).await?;
                }
            }
            Ok(())
        }
    }
}
