//! OS keychain store (macOS Keychain, Windows Credential Manager, Linux Secret Service).

use super::CredentialStore;
use crate::{KitError, KitResult};
use secrecy::{ExposeSecret, SecretString};

const CHUNK_MARKER_PREFIX: &str = "hzkit-chunked-v1:";
const MAX_CHUNK_BYTES: usize = 900;

/// Credential store backed by the operating system keychain.
pub struct OsKeychain {
    service: String,
}

impl OsKeychain {
    /// Create a store whose entries are grouped under `service`
    /// (for example `io.horizon-tech.dispatched`).
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> KitResult<keyring::Entry> {
        keyring::Entry::new(&self.service, key)
            .map_err(|e| KitError::SecretStore(format!("keychain entry: {e}")))
    }

    fn raw_put(&self, key: &str, value: &str) -> KitResult<()> {
        self.entry(key)?
            .set_password(value)
            .map_err(|e| KitError::SecretStore(format!("keychain put: {e}")))
    }

    fn raw_get(&self, key: &str) -> KitResult<Option<String>> {
        match self.entry(key)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KitError::SecretStore(format!("keychain get: {e}"))),
        }
    }

    fn raw_delete(&self, key: &str) -> KitResult<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KitError::SecretStore(format!("keychain delete: {e}"))),
        }
    }

    fn delete_chunks(&self, key: &str) -> KitResult<()> {
        if let Some(count) = self.raw_get(key)?.as_deref().and_then(parse_marker) {
            for i in 0..count {
                self.raw_delete(&chunk_key(key, i))?;
            }
        }
        Ok(())
    }
}

impl CredentialStore for OsKeychain {
    fn put(&self, key: &str, secret: &SecretString) -> KitResult<()> {
        let value = secret.expose_secret();
        self.delete_chunks(key)?;
        if value.len() <= MAX_CHUNK_BYTES && !value.starts_with(CHUNK_MARKER_PREFIX) {
            return self.raw_put(key, value);
        }
        let chunks = split_chunks(value);
        for (i, chunk) in chunks.iter().enumerate() {
            self.raw_put(&chunk_key(key, i), chunk)?;
        }
        self.raw_put(key, &format!("{CHUNK_MARKER_PREFIX}{}", chunks.len()))
    }

    fn get(&self, key: &str) -> KitResult<Option<SecretString>> {
        let Some(head) = self.raw_get(key)? else {
            return Ok(None);
        };
        let Some(count) = parse_marker(&head) else {
            return Ok(Some(SecretString::from(head)));
        };
        let mut joined = String::new();
        for i in 0..count {
            let part = self.raw_get(&chunk_key(key, i))?.ok_or_else(|| {
                KitError::SecretStore(format!("keychain chunk {i} of `{key}` is missing"))
            })?;
            joined.push_str(&part);
        }
        Ok(Some(SecretString::from(joined)))
    }

    fn delete(&self, key: &str) -> KitResult<()> {
        self.delete_chunks(key)?;
        self.raw_delete(key)
    }
}

fn chunk_key(key: &str, index: usize) -> String {
    format!("{key}::chunk::{index}")
}

fn parse_marker(value: &str) -> Option<usize> {
    value.strip_prefix(CHUNK_MARKER_PREFIX)?.parse().ok()
}

fn split_chunks(value: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        if !current.is_empty() && current.len() + ch.len_utf8() > MAX_CHUNK_BYTES {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_bytes_and_respects_limit() {
        let source = "x".repeat(MAX_CHUNK_BYTES * 2 + 17);
        let chunks = split_chunks(&source);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.len() <= MAX_CHUNK_BYTES));
        assert_eq!(chunks.concat(), source);
    }

    #[test]
    fn split_never_breaks_utf8() {
        let source = format!("{}å", "x".repeat(MAX_CHUNK_BYTES));
        assert_eq!(split_chunks(&source).concat(), source);
    }

    #[test]
    fn marker_roundtrip() {
        assert_eq!(parse_marker(&format!("{CHUNK_MARKER_PREFIX}3")), Some(3));
        assert_eq!(parse_marker("plain"), None);
    }

    /// Hits the real OS keychain. Run locally:
    /// `cargo test -p horizon-azure-kit -- --ignored keychain_roundtrip`
    #[test]
    #[ignore]
    fn keychain_roundtrip_large_secret() {
        let store = OsKeychain::new("io.horizon-tech.kit-test");
        let big = "t".repeat(3000);
        store
            .put("roundtrip", &SecretString::from(big.clone()))
            .unwrap();
        assert_eq!(
            store.get("roundtrip").unwrap().unwrap().expose_secret(),
            big
        );
        store.delete("roundtrip").unwrap();
        assert!(store.get("roundtrip").unwrap().is_none());
    }
}
