//! Secret storage. Secrets never touch plaintext config files.

#[cfg(feature = "keychain")]
mod keychain;

#[cfg(feature = "keychain")]
pub use keychain::OsKeychain;

use crate::KitResult;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::Mutex;

/// A key/value store for secrets.
pub trait CredentialStore: Send + Sync {
    /// Store `secret` under `key`, replacing any existing value.
    fn put(&self, key: &str, secret: &SecretString) -> KitResult<()>;
    /// Read the secret stored under `key`. `Ok(None)` if absent.
    fn get(&self, key: &str) -> KitResult<Option<SecretString>>;
    /// Remove the secret under `key`. Removing a missing key is not an error.
    fn delete(&self, key: &str) -> KitResult<()>;
}

/// In-memory store for tests and for `--no-keychain` sessions.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, String>>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for MemoryStore {
    fn put(&self, key: &str, secret: &SecretString) -> KitResult<()> {
        self.inner
            .lock()
            .expect("memory store poisoned")
            .insert(key.to_string(), secret.expose_secret().to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> KitResult<Option<SecretString>> {
        Ok(self
            .inner
            .lock()
            .expect("memory store poisoned")
            .get(key)
            .map(|v| SecretString::from(v.clone())))
    }

    fn delete(&self, key: &str) -> KitResult<()> {
        self.inner
            .lock()
            .expect("memory store poisoned")
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip_and_idempotent_delete() {
        let store = MemoryStore::new();
        store.put("k", &SecretString::from("v")).unwrap();
        assert_eq!(store.get("k").unwrap().unwrap().expose_secret(), "v");
        store.delete("k").unwrap();
        store.delete("k").unwrap();
        assert!(store.get("k").unwrap().is_none());
    }

    #[test]
    fn trait_is_object_safe() {
        fn take(_: &dyn CredentialStore) {}
        take(&MemoryStore::new());
    }
}
