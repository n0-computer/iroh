use iroh_identity::{Error, LocalIdentity, Registry, RemotePolicy};

#[test]
fn credentials_roundtrip_and_private_files_preserve_identity() {
    let registry = Registry::builtins(vec![1, 2]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    for (index, identity) in [
        LocalIdentity::ed25519(iroh_base::SecretKey::generate(), &registry).unwrap(),
        LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = identity.to_bytes().unwrap();
        assert_eq!(format!("{bytes:?}"), "SecretBytes(REDACTED)");
        let recovered = LocalIdentity::from_bytes(bytes.as_bytes(), &registry).unwrap();
        assert_eq!(identity.id(), recovered.id());
        let signature = recovered.sign(b"credential persistence test").unwrap();
        assert_eq!(
            registry
                .verify_proof(
                    identity.public_key().as_ref(),
                    b"credential persistence test",
                    &signature
                )
                .unwrap(),
            identity.id()
        );
        let path = directory.path().join(format!("key-{index}"));
        identity.save(&path).unwrap();
        assert!(identity.save(&path).is_err());
        assert_eq!(
            LocalIdentity::load(&path, &registry).unwrap().id(),
            identity.id()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                LocalIdentity::load(&path, &registry),
                Err(Error::InsecureKeyFile)
            ));
        }
    }
}

#[test]
fn malformed_and_relabelled_credentials_are_rejected() {
    let registry = Registry::builtins(vec![1, 2]).unwrap();
    let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    let bytes = identity.to_bytes().unwrap();
    for len in 0..bytes.as_bytes().len() {
        assert!(LocalIdentity::from_bytes(&bytes.as_bytes()[..len], &registry).is_err());
    }
    let mut wrong_suite = bytes.as_bytes().to_vec();
    wrong_suite[6] = 1;
    assert!(LocalIdentity::from_bytes(&wrong_suite, &registry).is_err());
    assert!(LocalIdentity::from_bytes(&vec![0; 16385], &registry).is_err());
}

#[test]
fn remote_identity_authorization_does_not_restrict_local_credentials() {
    let registry = Registry::builtins(vec![1, 2]).unwrap();
    let permitted = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    let other = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    let restricted = registry
        .with_remote_policy(RemotePolicy::new([2]).allow_peers([permitted.id()]))
        .unwrap();
    assert_eq!(
        restricted
            .identify(permitted.public_key().as_ref())
            .unwrap(),
        permitted.id()
    );
    assert!(matches!(
        restricted.identify(other.public_key().as_ref()),
        Err(Error::Unauthorized)
    ));
    assert!(LocalIdentity::ed25519(iroh_base::SecretKey::generate(), &restricted).is_ok());
    assert!(
        restricted
            .identify_local(other.public_key().as_ref())
            .is_ok()
    );
}
