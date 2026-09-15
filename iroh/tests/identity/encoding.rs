use std::sync::Arc;

use iroh::identity::{BuiltinAlgorithm, Error, IdentityAlgorithm, LocalIdentity, PeerId, Registry};
use iroh_base::{PublicKey, SecretKey};

#[test]
fn legacy_encodings_and_conversion_are_unchanged() {
    let key = SecretKey::from_bytes(&[0; 32]);
    let public = key.public();
    let id = PeerId::from(public);
    assert_eq!(
        id.to_string(),
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
    );
    assert_eq!(id.to_string().parse::<PeerId>().unwrap(), id);
    assert_eq!(PublicKey::try_from(id).unwrap(), public);
    assert_eq!(postcard::to_stdvec(&public).unwrap(), public.as_bytes());
    assert_eq!(PeerId::from_bytes(&id.to_bytes()).unwrap(), id);
    assert_eq!(id.to_bytes().len(), 33); // New envelope only.
    let registry = Registry::builtins(vec![1, 2]).unwrap();
    assert_eq!(LocalIdentity::ed25519(key, &registry).unwrap().id(), id);
}

#[test]
fn commitment_has_an_independently_computed_vector() {
    // SHA-384 vector independently computed with GNU sha384sum. This synthetic
    // public key tests encoding only; it is never used to authenticate a peer.
    let spki = rustls::sign::public_key_to_spki(&rustls::pki_types::alg_id::ML_DSA_65, [0; 1952]);
    let registry = Registry::builtins(vec![2]).unwrap();
    let id = registry.identify(spki.as_ref()).unwrap();
    assert_eq!(
        id.to_string(),
        concat!(
            "iroh-pid1-0101",
            "b5eae4b113a1d2556cdf07cf7c0e34d6c7bb2052f1d97e5e8cce6be3b201f8eef116388069ec74903bcfeaebda80d8fc"
        )
    );
    assert_eq!(id.to_string().parse::<PeerId>().unwrap(), id);
    assert_eq!(PeerId::from_bytes(&id.to_bytes()).unwrap(), id);
    assert!(PublicKey::try_from(id).is_err());
    let changed =
        rustls::sign::public_key_to_spki(&rustls::pki_types::alg_id::ML_DSA_65, [1; 1952]);
    assert_ne!(registry.identify(changed.as_ref()).unwrap(), id);
}

#[test]
fn invalid_envelopes_and_noncanonical_keys_fail() {
    for bytes in [vec![], vec![2; 50], vec![1, 2], vec![0; 32], vec![1; 51]] {
        assert!(PeerId::from_bytes(&bytes).is_err());
    }
    for text in [
        "iroh-pid2-0101",
        "iroh-pid1-00",
        "iroh-pid1-",
        "iroh-pid1-01ZZ",
    ] {
        assert!(text.parse::<PeerId>().is_err());
    }
    let id = PeerId::V1([0xab; 48]);
    assert!(id.to_string().to_uppercase().parse::<PeerId>().is_err());
    let upper_hex = format!("iroh-pid1-{}", id.to_string()[10..].to_uppercase());
    assert!(upper_hex.parse::<PeerId>().is_err());
    let registry = Registry::builtins(vec![1, 2]).unwrap();
    let valid = rustls::sign::public_key_to_spki(&rustls::pki_types::alg_id::ML_DSA_65, [0; 1952]);
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert!(registry.identify(&trailing).is_err());
    assert!(registry.identify(&valid.as_ref()[1..]).is_err());
    assert!(registry.identify(&[0; 8193]).is_err());
    let wrong_oid =
        rustls::sign::public_key_to_spki(&rustls::pki_types::alg_id::ED25519, [0; 1952]);
    assert!(registry.identify(wrong_oid.as_ref()).is_err());
}

#[test]
fn registry_rejects_duplicates_and_policy_rejects_disallowed_keys() {
    assert!(matches!(
        Registry::new(
            vec![
                Arc::new(BuiltinAlgorithm::MlDsa65),
                Arc::new(BuiltinAlgorithm::MlDsa65)
            ],
            vec![2]
        ),
        Err(Error::DuplicateSuite)
    ));
    assert!(Registry::builtins(vec![42]).is_err());
    assert!(Registry::builtins(vec![]).is_err());
    let registry = Registry::builtins(vec![2]).unwrap();
    let key = SecretKey::generate();
    LocalIdentity::ed25519(key.clone(), &registry).unwrap();
    let spki = rustls::sign::public_key_to_spki(
        &rustls::pki_types::alg_id::ED25519,
        key.public().as_bytes(),
    );
    assert!(matches!(
        registry.identify(spki.as_ref()),
        Err(Error::Suite)
    ));
}

#[derive(Debug)]
struct AlternateSuite;

impl IdentityAlgorithm for AlternateSuite {
    fn suite_id(&self) -> u16 {
        500
    }
    fn tls_scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ML_DSA_65
    }
    fn public_key<'a>(&self, spki: &'a [u8]) -> Result<&'a [u8], Error> {
        BuiltinAlgorithm::MlDsa65.public_key(spki)
    }
    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        BuiltinAlgorithm::MlDsa65.verify(key, message, signature)
    }
}

#[test]
fn commitment_binds_suite_and_registry_accepts_external_adapters() {
    let spki = rustls::sign::public_key_to_spki(&rustls::pki_types::alg_id::ML_DSA_65, [0; 1952]);
    let builtin = Registry::builtins(vec![2]).unwrap();
    let external = Registry::new(vec![Arc::new(AlternateSuite)], vec![500]).unwrap();
    assert_ne!(
        builtin.identify(spki.as_ref()).unwrap(),
        external.identify(spki.as_ref()).unwrap()
    );
}

#[test]
fn ml_dsa_signatures_reject_tampering_and_wrong_keys() {
    use aws_lc_rs::signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};
    let pair = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
    let other = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
    let mut signature = vec![0; 3309];
    let len = pair.sign(b"identity proof", &mut signature).unwrap();
    assert_eq!(len, signature.len());
    let alg = BuiltinAlgorithm::MlDsa65;
    alg.verify(
        pair.public_key().as_ref(),
        b"identity proof",
        signature.as_ref(),
    )
    .unwrap();
    assert!(
        alg.verify(
            pair.public_key().as_ref(),
            b"different proof",
            signature.as_ref()
        )
        .is_err()
    );
    assert!(
        alg.verify(
            other.public_key().as_ref(),
            b"identity proof",
            signature.as_ref()
        )
        .is_err()
    );
    assert!(
        alg.verify(pair.public_key().as_ref(), b"identity proof", &[0; 3309])
            .is_err()
    );
}
