//! Primitives for [Private Area Intersection]
//!
//! * Uses ristretto255 and SHA512 for `hash_into_group`.
//!
//! TODO: Use edwards25519 with [RFC 9380] instead.
//!
//! [Private Area Intersection]: https://willowprotocol.org/specs/pai/index.html
//! [RFC 9380]: https://www.rfc-editor.org/rfc/rfc9380

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};

use crate::{
    proto::{
        grouping::SubspaceArea,
        sync::ReadCapability,
        willow::{NamespaceId, Path, SubspaceId},
    },
    util::codec::Encoder,
};

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
        let encoded = fragment.encode().expect("encoding not to fail");
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
        let granted_namespace = cap.granted_namespace().id();
        let granted_path = granted_area.path.clone();

        match granted_area.subspace {
            SubspaceArea::Any => FragmentKit::Complete(granted_namespace, granted_path),
            SubspaceArea::Id(granted_subspace) => {
                FragmentKit::Selective(granted_namespace, granted_subspace, granted_path)
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
    pub fn into_parts(self) -> (NamespaceId, SubspaceArea, Path) {
        match self {
            Fragment::Pair((namespace_id, path)) => (namespace_id, SubspaceArea::Any, path),
            Fragment::Triple((namespace_id, subspace_id, path)) => {
                (namespace_id, SubspaceArea::Id(subspace_id), path)
            }
        }
    }
}

impl Encoder for Fragment {
    fn encoded_len(&self) -> usize {
        match self {
            Fragment::Pair((_, path)) => NamespaceId::LENGTH + path.encoded_len(),
            Fragment::Triple((_, _, path)) => {
                NamespaceId::LENGTH + SubspaceId::LENGTH + path.encoded_len()
            }
        }
    }
    fn encode_into<W: std::io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
        match self {
            Fragment::Pair((namespace_id, path)) => {
                out.write_all(namespace_id.as_bytes())?;
                path.encode_into(out)?;
            }
            Fragment::Triple((namespace_id, subspace_id, path)) => {
                out.write_all(namespace_id.as_bytes())?;
                out.write_all(subspace_id.as_bytes())?;
                path.encode_into(out)?;
            }
        }
        Ok(())
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
                    .into_iter()
                    .map(|prefix| (namespace_id, prefix))
                    .collect();
                FragmentSet::Complete(pairs)
            }
            FragmentKit::Selective(namespace_id, subspace_id, path) => {
                let all_prefixes = path.all_prefixes();
                let primary = all_prefixes
                    .iter()
                    .cloned()
                    .map(|prefix| (namespace_id, subspace_id, prefix))
                    .collect();
                let secondary = all_prefixes
                    .into_iter()
                    .map(|prefix| (namespace_id, prefix))
                    .collect();
                FragmentSet::Selective { primary, secondary }
            }
        }
    }
}
