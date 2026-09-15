use iroh_identity::{Error, LocalIdentity, Registry, TrustStore};

#[test]
fn trust_migration_is_explicit_persistent_and_checks_the_old_pin() {
    let registry = Registry::builtins(vec![1, 2]).unwrap();
    let old = LocalIdentity::ed25519(iroh_base::SecretKey::generate(), &registry)
        .unwrap()
        .id();
    let new = LocalIdentity::generate_ml_dsa65(&registry).unwrap().id();
    let mut store = TrustStore::default();
    store.trust("service", old).unwrap();
    assert!(matches!(
        store.trust("service", new),
        Err(Error::TrustMismatch)
    ));
    assert!(matches!(
        store.migrate("service", new, old),
        Err(Error::TrustMismatch)
    ));
    assert_eq!(store.get("service"), Some(old));
    store.migrate("service", old, new).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("trust");
    store.save(&path).unwrap();
    let mut restored = TrustStore::load(&path).unwrap();
    assert_eq!(restored.get("service"), Some(new));
    assert!(matches!(
        restored.revoke("service", old),
        Err(Error::TrustMismatch)
    ));
    restored.revoke("service", new).unwrap();
    restored.save(&path).unwrap();
    assert_eq!(TrustStore::load(&path).unwrap().get("service"), None);
}

#[test]
fn duplicate_and_noncanonical_pins_are_rejected() {
    let registry = Registry::builtins(vec![1]).unwrap();
    let id = LocalIdentity::ed25519(iroh_base::SecretKey::generate(), &registry)
        .unwrap()
        .id();
    let duplicate = format!("iroh trust store v1\n61\t{id}\n61\t{id}\n");
    assert!(TrustStore::from_bytes(duplicate.as_bytes()).is_err());
    let truncated = format!("iroh trust store v1\n61\t{id}");
    assert!(TrustStore::from_bytes(truncated.as_bytes()).is_err());
}
