//! OS keychain store (macOS Keychain, Windows Credential Manager, Linux Secret Service).
//!
//! Some keychains cap entry size, so long values are split into chunks. Writes
//! are crash-safe: new chunks are written under a fresh generation id, the head
//! entry (plain value or marker) is written last as the commit point, and only
//! then are the previous generation's chunks removed. A failure before the
//! commit leaves the old value readable.

use super::CredentialStore;
use crate::{KitError, KitResult};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

const CHUNK_MARKER_PREFIX: &str = "hzkit-chunked-v1:";
const MAX_CHUNK_BYTES: usize = 900;
const MAX_CHUNKS: usize = 64;

/// Raw string entries of a keychain-like backend.
trait RawEntries: Send + Sync {
    fn raw_put(&self, key: &str, value: &str) -> KitResult<()>;
    fn raw_get(&self, key: &str) -> KitResult<Option<String>>;
    fn raw_delete(&self, key: &str) -> KitResult<()>;
}

/// `RawEntries` backed by the `keyring` crate.
struct KeyringEntries {
    service: String,
}

impl KeyringEntries {
    fn entry(&self, key: &str) -> KitResult<keyring::Entry> {
        keyring::Entry::new(&self.service, key)
            .map_err(|e| KitError::SecretStore(format!("keychain entry: {e}")))
    }
}

impl RawEntries for KeyringEntries {
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
}

/// Chunking orchestration over any `RawEntries` backend.
struct Chunked<R> {
    raw: R,
}

impl<R: RawEntries> Chunked<R> {
    fn delete_chunks(&self, key: &str, marker: &Marker) -> KitResult<()> {
        for i in 0..marker.count {
            self.raw
                .raw_delete(&chunk_key(key, &marker.generation, i))?;
        }
        Ok(())
    }
}

impl<R: RawEntries> CredentialStore for Chunked<R> {
    fn put(&self, key: &str, secret: &SecretString) -> KitResult<()> {
        let value = secret.expose_secret();
        let old = match self.raw.raw_get(key)? {
            Some(head) => parse_marker(&head),
            None => None,
        };

        if value.len() <= MAX_CHUNK_BYTES && !value.starts_with(CHUNK_MARKER_PREFIX) {
            // Commit point: the plain value replaces whatever was there.
            self.raw.raw_put(key, value)?;
        } else {
            let chunks = split_chunks(value);
            if chunks.len() > MAX_CHUNKS {
                return Err(KitError::SecretStore(format!(
                    "secret `{key}` is too large for the keychain ({} bytes, limit {} bytes)",
                    value.len(),
                    MAX_CHUNKS * MAX_CHUNK_BYTES
                )));
            }
            let generation = new_gen();
            for (i, chunk) in chunks.iter().enumerate() {
                self.raw.raw_put(&chunk_key(key, &generation, i), chunk)?;
            }
            // Commit point: the marker switches the head to the new generation.
            let marker = Marker {
                generation,
                count: chunks.len(),
            };
            self.raw.raw_put(key, &format_marker(&marker))?;
        }

        // Old generation is unreachable now. Cleanup is best effort: orphan
        // chunks are harmless, the head already points at the new value.
        let cleanup = old.map_or(Ok(()), |old| self.delete_chunks(key, &old));
        if let Err(e) = cleanup {
            tracing::warn!(key, error = %e, "could not remove previous keychain chunks");
        }
        Ok(())
    }

    fn get(&self, key: &str) -> KitResult<Option<SecretString>> {
        let Some(head) = self.raw.raw_get(key)? else {
            return Ok(None);
        };
        if !head.starts_with(CHUNK_MARKER_PREFIX) {
            return Ok(Some(SecretString::from(head)));
        }
        let marker = parse_marker(&head).ok_or_else(|| {
            KitError::SecretStore(format!("keychain marker for `{key}` is corrupt"))
        })?;
        let mut joined = String::new();
        for i in 0..marker.count {
            let part = self
                .raw
                .raw_get(&chunk_key(key, &marker.generation, i))?
                .ok_or_else(|| {
                    KitError::SecretStore(format!("keychain chunk {i} of `{key}` is missing"))
                })?;
            joined.push_str(&part);
        }
        Ok(Some(SecretString::from(joined)))
    }

    fn delete(&self, key: &str) -> KitResult<()> {
        // Head first: a dangling marker is not allowed, orphan chunks are.
        let head = self.raw.raw_get(key)?;
        self.raw.raw_delete(key)?;
        if let Some(marker) = head.as_deref().and_then(parse_marker) {
            self.delete_chunks(key, &marker)?;
        }
        Ok(())
    }
}

/// Credential store backed by the operating system keychain.
pub struct OsKeychain {
    store: Chunked<KeyringEntries>,
}

impl OsKeychain {
    /// Create a store whose entries are grouped under `service`
    /// (for example `io.horizon-tech.dispatched`).
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            store: Chunked {
                raw: KeyringEntries {
                    service: service.into(),
                },
            },
        }
    }
}

impl CredentialStore for OsKeychain {
    fn put(&self, key: &str, secret: &SecretString) -> KitResult<()> {
        self.store.put(key, secret)
    }

    fn get(&self, key: &str) -> KitResult<Option<SecretString>> {
        self.store.get(key)
    }

    fn delete(&self, key: &str) -> KitResult<()> {
        self.store.delete(key)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Marker {
    generation: String,
    count: usize,
}

fn new_gen() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn chunk_key(key: &str, generation: &str, index: usize) -> String {
    format!("{key}::chunk::{generation}::{index}")
}

fn format_marker(marker: &Marker) -> String {
    format!(
        "{CHUNK_MARKER_PREFIX}{}:{}",
        marker.generation, marker.count
    )
}

/// Parse `hzkit-chunked-v1:{generation}:{count}`. Anything malformed, or a count
/// outside `1..=MAX_CHUNKS`, is treated as corrupt (`None`).
fn parse_marker(value: &str) -> Option<Marker> {
    let rest = value.strip_prefix(CHUNK_MARKER_PREFIX)?;
    let (generation, count) = rest.split_once(':')?;
    if generation.len() != 8 || !generation.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let count: usize = count.parse().ok()?;
    if count == 0 || count > MAX_CHUNKS {
        return None;
    }
    Some(Marker {
        generation: generation.to_string(),
        count,
    })
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// In-memory `RawEntries` with failure injection.
    #[derive(Default)]
    struct FakeRaw {
        map: Mutex<HashMap<String, String>>,
        /// Successful puts still allowed before the next put fails. `None` = unlimited.
        budget: Mutex<Option<usize>>,
    }

    impl FakeRaw {
        /// Allow `n` more successful puts, then fail the following one.
        fn fail_after(&self, n: usize) {
            *self.budget.lock().unwrap() = Some(n);
        }

        fn keys(&self) -> Vec<String> {
            let mut keys: Vec<String> = self.map.lock().unwrap().keys().cloned().collect();
            keys.sort();
            keys
        }
    }

    impl RawEntries for FakeRaw {
        fn raw_put(&self, key: &str, value: &str) -> KitResult<()> {
            {
                let mut budget = self.budget.lock().unwrap();
                if let Some(n) = budget.as_mut() {
                    if *n == 0 {
                        return Err(KitError::SecretStore("injected put failure".into()));
                    }
                    *n -= 1;
                }
            }
            self.map
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn raw_get(&self, key: &str) -> KitResult<Option<String>> {
            Ok(self.map.lock().unwrap().get(key).cloned())
        }

        fn raw_delete(&self, key: &str) -> KitResult<()> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// Lets a test keep a handle on the fake while the store owns a clone.
    impl<T: RawEntries> RawEntries for Arc<T> {
        fn raw_put(&self, key: &str, value: &str) -> KitResult<()> {
            (**self).raw_put(key, value)
        }
        fn raw_get(&self, key: &str) -> KitResult<Option<String>> {
            (**self).raw_get(key)
        }
        fn raw_delete(&self, key: &str) -> KitResult<()> {
            (**self).raw_delete(key)
        }
    }

    fn fixture() -> (Arc<FakeRaw>, Chunked<Arc<FakeRaw>>) {
        let fake = Arc::new(FakeRaw::default());
        let store = Chunked { raw: fake.clone() };
        (fake, store)
    }

    fn read(store: &impl CredentialStore, key: &str) -> Option<String> {
        store
            .get(key)
            .unwrap()
            .map(|s| s.expose_secret().to_string())
    }

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
        let chunks = split_chunks(&source);
        assert!(chunks.iter().all(|c| c.len() <= MAX_CHUNK_BYTES));
        assert_eq!(chunks.concat(), source);
    }

    #[test]
    fn marker_roundtrip() {
        let marker = Marker {
            generation: "0a1b2c3d".into(),
            count: 3,
        };
        assert_eq!(parse_marker(&format_marker(&marker)), Some(marker));
        assert_eq!(parse_marker("plain"), None);
        assert_eq!(parse_marker("hzkit-chunked-v1:0a1b2c3d:0"), None);
        assert_eq!(parse_marker("hzkit-chunked-v1:0a1b2c3d:99999"), None);
        assert_eq!(parse_marker("hzkit-chunked-v1:short:3"), None);
    }

    #[test]
    fn large_secret_roundtrip() {
        let (_fake, store) = fixture();
        let big = "t".repeat(3000);
        store.put("k", &SecretString::from(big.clone())).unwrap();
        assert_eq!(read(&store, "k").unwrap(), big);
        store.delete("k").unwrap();
        assert!(store.get("k").unwrap().is_none());
    }

    #[test]
    fn shrink_from_chunked_to_plain_leaves_no_chunks() {
        let (fake, store) = fixture();
        store
            .put("k", &SecretString::from("a".repeat(3000)))
            .unwrap();
        store.put("k", &SecretString::from("small")).unwrap();
        assert_eq!(read(&store, "k").unwrap(), "small");
        assert_eq!(fake.keys(), vec!["k".to_string()]);
    }

    #[test]
    fn grow_from_plain_to_chunked() {
        let (fake, store) = fixture();
        store.put("k", &SecretString::from("small")).unwrap();
        let big = "b".repeat(2000);
        store.put("k", &SecretString::from(big.clone())).unwrap();
        assert_eq!(read(&store, "k").unwrap(), big);
        // head + 3 chunks (900 + 900 + 200)
        assert_eq!(fake.keys().len(), 4);
    }

    #[test]
    fn plain_value_starting_with_marker_prefix() {
        let (fake, store) = fixture();
        let tricky = "hzkit-chunked-v1:deadbeef:3";
        store.put("k", &SecretString::from(tricky)).unwrap();
        assert_eq!(read(&store, "k").unwrap(), tricky);
        assert_eq!(fake.keys().len(), 2); // head + one chunk
    }

    #[test]
    fn failed_second_chunk_write_keeps_old_value_readable() {
        let (fake, store) = fixture();
        let old = "a".repeat(2000);
        store.put("k", &SecretString::from(old.clone())).unwrap();

        // New put: chunk 0 succeeds, chunk 1 fails.
        fake.fail_after(1);
        let result = store.put("k", &SecretString::from("b".repeat(2000)));
        assert!(result.is_err());
        assert_eq!(read(&store, "k").unwrap(), old);
    }

    #[test]
    fn failed_commit_write_keeps_old_value_readable() {
        let (fake, store) = fixture();
        let old = "a".repeat(2000);
        store.put("k", &SecretString::from(old.clone())).unwrap();

        // New put: all 3 chunks succeed, the marker (commit) fails.
        fake.fail_after(3);
        assert!(
            store
                .put("k", &SecretString::from("b".repeat(2000)))
                .is_err()
        );
        assert_eq!(read(&store, "k").unwrap(), old);
    }

    #[test]
    fn delete_removes_everything() {
        let (fake, store) = fixture();
        store
            .put("k", &SecretString::from("c".repeat(3000)))
            .unwrap();
        store.delete("k").unwrap();
        assert!(fake.keys().is_empty());
        store.delete("k").unwrap();
    }

    #[test]
    fn oversized_secret_is_rejected_before_any_write() {
        let (fake, store) = fixture();
        let too_big = "d".repeat(MAX_CHUNKS * MAX_CHUNK_BYTES + 1);
        assert!(store.put("k", &SecretString::from(too_big)).is_err());
        assert!(fake.keys().is_empty());
    }

    #[test]
    fn marker_with_huge_count_is_rejected_without_looping() {
        let (fake, store) = fixture();
        fake.raw_put("k", "hzkit-chunked-v1:deadbeef:99999")
            .unwrap();
        let err = store.get("k").unwrap_err().to_string();
        assert!(err.contains("`k`"), "error should name the key: {err}");
        // Delete still clears the corrupt head.
        store.delete("k").unwrap();
        assert!(fake.keys().is_empty());
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
