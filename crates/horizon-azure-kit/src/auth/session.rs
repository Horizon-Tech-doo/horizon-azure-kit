//! A signed-in Entra identity: interactive login, cached per-scope access
//! tokens, and logout. Refresh tokens live in the credential store; access
//! tokens live only in memory.

use super::browser::{LoopbackRedirect, Pkce};
use super::claims::parse_identity_claims;
use super::oauth::{DeviceCodeResponse, OAuthClient, TokenResponse};
use crate::secrets::CredentialStore;
use crate::{AzureCloud, KitError, KitResult};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

/// Microsoft's public "Azure CLI" client id. Pre-consented in most tenants and
/// allows `http://localhost` loopback redirects.
pub const AZURE_CLI_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

const LOGIN_EXTRA_SCOPES: &str = "offline_access openid profile";
const REFRESH_MARGIN: time::Duration = time::Duration::minutes(5);

/// A remembered sign-in. Products persist this record themselves (it holds no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    /// Stable id: the user's object id, or `tenant:upn` if absent.
    pub id: String,
    /// User principal name / e-mail.
    pub user_principal: String,
    /// Home tenant of the sign-in.
    pub tenant_id: String,
    /// Display name, if the token carried one.
    pub display_name: Option<String>,
    /// Cloud the sign-in belongs to.
    pub cloud: AzureCloud,
}

/// An access token for one scope.
#[derive(Debug, Clone)]
pub struct AccessToken {
    /// The bearer token.
    pub token: SecretString,
    /// Expiry instant (UTC).
    pub expires_on: OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
struct StoredRefresh {
    refresh_token: String,
    tenant_id: String,
    client_id: String,
}

type CacheKey = (String, String, String); // (sign-in id, tenant, scope)

/// Mutable session state, guarded by one lock that is never held across an await.
#[derive(Default)]
struct SessionState {
    cache: HashMap<CacheKey, AccessToken>,
    /// Bumped by `logout` and `finish_login`, so a refresh that started before a
    /// sign-out or a fresh sign-in can detect it.
    generations: HashMap<String, u64>,
}

/// Entra sign-in manager for one cloud.
pub struct EntraSession {
    oauth: OAuthClient,
    cloud: AzureCloud,
    secrets: Arc<dyn CredentialStore>,
    key_prefix: String,
    state: Mutex<SessionState>,
}

impl EntraSession {
    /// Build a session manager. `key_prefix` namespaces keychain entries per product.
    pub fn new(
        cloud: AzureCloud,
        secrets: Arc<dyn CredentialStore>,
        key_prefix: impl Into<String>,
    ) -> Self {
        Self {
            oauth: OAuthClient::new(cloud.authority_host(), AZURE_CLI_CLIENT_ID),
            cloud,
            secrets,
            key_prefix: key_prefix.into(),
            state: Mutex::new(SessionState::default()),
        }
    }

    /// Replace the OAuth client (tests, custom client ids).
    pub fn with_oauth(mut self, oauth: OAuthClient) -> Self {
        self.oauth = oauth;
        self
    }

    fn login_scope(&self) -> String {
        format!("{} {LOGIN_EXTRA_SCOPES}", self.cloud.arm_scope())
    }

    fn key(&self, sign_in_id: &str) -> String {
        format!("{}:entra:{sign_in_id}", self.key_prefix)
    }

    /// Device-code sign-in. `on_prompt` shows the code and URL to the user.
    pub async fn login_device_code(
        &self,
        tenant: &str,
        on_prompt: impl FnOnce(&DeviceCodeResponse),
    ) -> KitResult<SignIn> {
        let scope = self.login_scope();
        let dc = self.oauth.start_device_code(tenant, &scope).await?;
        on_prompt(&dc);
        let token = self.oauth.poll_device_code(tenant, &dc).await?;
        self.finish_login(tenant, token)
    }

    /// Browser sign-in (authorization code + PKCE). `open_url` must open the URL
    /// in the user's browser.
    pub async fn login_browser(
        &self,
        tenant: &str,
        open_url: impl FnOnce(&str),
    ) -> KitResult<SignIn> {
        let redirect = LoopbackRedirect::bind().await?;
        let redirect_uri = redirect.redirect_uri();
        let pkce = Pkce::generate();
        let state = uuid::Uuid::new_v4().simple().to_string();
        let scope = self.login_scope();
        open_url(
            &self
                .oauth
                .authorize_url(tenant, &scope, &redirect_uri, &state, &pkce.challenge),
        );
        let code = redirect
            .wait_for_code(&state, Duration::from_secs(300))
            .await?;
        let token = self
            .oauth
            .exchange_code(tenant, &code, &redirect_uri, &pkce.verifier, &scope)
            .await?;
        self.finish_login(tenant, token)
    }

    fn finish_login(&self, requested_tenant: &str, token: TokenResponse) -> KitResult<SignIn> {
        let mut claims = token
            .id_token
            .as_deref()
            .map(parse_identity_claims)
            .unwrap_or_default();
        if claims.user_principal.is_none() {
            claims = parse_identity_claims(&token.access_token);
        }
        let tenant_id = claims
            .tenant_id
            .unwrap_or_else(|| requested_tenant.to_string());
        let user_principal = claims
            .user_principal
            .unwrap_or_else(|| "unknown".to_string());
        let id = claims
            .object_id
            .unwrap_or_else(|| format!("{tenant_id}:{user_principal}"));
        let refresh_token = token
            .refresh_token
            .ok_or_else(|| KitError::AuthFailed("Entra returned no refresh token".into()))?;
        let stored = StoredRefresh {
            refresh_token,
            tenant_id: tenant_id.clone(),
            client_id: self.oauth.client_id().to_string(),
        };
        let json = serde_json::to_string(&stored).expect("StoredRefresh serializes");
        {
            // Bump under the lock before storing, so a refresh that began
            // earlier cannot delete or overwrite this fresh sign-in.
            let mut state = self.state.lock().expect("session state poisoned");
            *state.generations.entry(id.clone()).or_insert(0) += 1;
            state.cache.retain(|(cached_id, _, _), _| cached_id != &id);
            self.secrets
                .put(&self.key(&id), &SecretString::from(json))?;
        }
        Ok(SignIn {
            id,
            user_principal,
            tenant_id,
            display_name: claims.name,
            cloud: self.cloud,
        })
    }

    fn generation(&self, sign_in_id: &str) -> u64 {
        self.state
            .lock()
            .expect("session state poisoned")
            .generations
            .get(sign_in_id)
            .copied()
            .unwrap_or(0)
    }

    fn load(&self, sign_in: &SignIn) -> KitResult<StoredRefresh> {
        let secret = self.secrets.get(&self.key(&sign_in.id))?.ok_or_else(|| {
            KitError::NotSignedIn(format!("{} is not signed in", sign_in.user_principal))
        })?;
        serde_json::from_str(secret.expose_secret())
            .map_err(|e| KitError::SecretStore(format!("stored sign-in is unreadable: {e}")))
    }

    /// Access token for `scope` (e.g. `https://servicebus.azure.net/.default`),
    /// in `tenant` or the sign-in's home tenant. Served from memory until 5
    /// minutes before expiry.
    pub async fn token_for(
        &self,
        sign_in: &SignIn,
        tenant: Option<&str>,
        scope: &str,
    ) -> KitResult<AccessToken> {
        // Snapshot before `load`: a logout or login after this point changes
        // the generation, so the checks below detect it.
        let generation = self.generation(&sign_in.id);
        let stored = self.load(sign_in)?;
        if stored.client_id != self.oauth.client_id() {
            return Err(KitError::NotSignedIn(format!(
                "{} was signed in with a different client; sign in again",
                sign_in.user_principal
            )));
        }
        let home = tenant.is_none_or(|t| t == stored.tenant_id);
        let tenant = tenant.unwrap_or(&stored.tenant_id).to_string();
        let key = (sign_in.id.clone(), tenant.clone(), scope.to_string());
        {
            let state = self.state.lock().expect("session state poisoned");
            if let Some(hit) = state.cache.get(&key)
                && hit.expires_on - OffsetDateTime::now_utc() > REFRESH_MARGIN
            {
                return Ok(hit.clone());
            }
        }
        let resp = match self
            .oauth
            .refresh(
                &tenant,
                &stored.refresh_token,
                &format!("{scope} offline_access"),
            )
            .await
        {
            Ok(resp) => resp,
            Err(KitError::NotSignedIn(msg)) => {
                if home {
                    // A revoked or expired home session is forgotten, so
                    // `is_signed_in` reports false. Skipped if the user signed
                    // out (or signed in again) while the refresh was in flight.
                    let state = self.state.lock().expect("session state poisoned");
                    if state.generations.get(&sign_in.id).copied().unwrap_or(0) == generation {
                        self.secrets.delete(&self.key(&sign_in.id))?;
                    }
                }
                return Err(KitError::NotSignedIn(format!(
                    "{}: {msg}",
                    sign_in.user_principal
                )));
            }
            Err(e) => return Err(e),
        };
        let mut state = self.state.lock().expect("session state poisoned");
        if state.generations.get(&sign_in.id).copied().unwrap_or(0) != generation {
            return Err(KitError::NotSignedIn(format!(
                "{} signed out",
                sign_in.user_principal
            )));
        }
        // Only home-tenant rotations replace the stored token; a token minted
        // for another tenant must not overwrite the home refresh token.
        if home
            && let Some(rotated) = resp
                .refresh_token
                .as_ref()
                .filter(|rt| **rt != stored.refresh_token)
        {
            let updated = StoredRefresh {
                refresh_token: rotated.clone(),
                ..stored
            };
            let json = serde_json::to_string(&updated).expect("StoredRefresh serializes");
            self.secrets
                .put(&self.key(&sign_in.id), &SecretString::from(json))?;
        }
        let token = AccessToken {
            token: SecretString::from(resp.access_token),
            expires_on: OffsetDateTime::now_utc() + time::Duration::seconds(resp.expires_in as i64),
        };
        state.cache.insert(key, token.clone());
        Ok(token)
    }

    /// Whether a refresh token is stored for this sign-in.
    pub fn is_signed_in(&self, sign_in: &SignIn) -> KitResult<bool> {
        Ok(self.secrets.get(&self.key(&sign_in.id))?.is_some())
    }

    /// Forget the sign-in: delete its refresh token and cached access tokens.
    pub fn logout(&self, sign_in: &SignIn) -> KitResult<()> {
        let mut state = self.state.lock().expect("session state poisoned");
        *state.generations.entry(sign_in.id.clone()).or_insert(0) += 1;
        self.secrets.delete(&self.key(&sign_in.id))?;
        state.cache.retain(|(id, _, _), _| id != &sign_in.id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::claims::test_jwt;
    use crate::secrets::MemoryStore;
    use mockito::Matcher;

    fn session(server: &mockito::Server, store: Arc<MemoryStore>) -> EntraSession {
        EntraSession::new(AzureCloud::Public, store, "test")
            .with_oauth(OAuthClient::new(server.url(), "cid"))
    }

    async fn mock_device_login(server: &mut mockito::Server) -> (mockito::Mock, mockito::Mock) {
        let dc = server
            .mock("POST", "/organizations/oauth2/v2.0/devicecode")
            .with_status(200)
            .with_body(r#"{"user_code":"U","verification_uri":"V","device_code":"dc","expires_in":30,"interval":1,"message":"M"}"#)
            .create_async()
            .await;
        let id_token = test_jwt(
            r#"{"tid":"tenant-1","oid":"oid-1","preferred_username":"a@x.io","name":"A"}"#,
        );
        let tok = server
            .mock("POST", "/organizations/oauth2/v2.0/token")
            .match_body(Matcher::UrlEncoded("device_code".into(), "dc".into()))
            .with_status(200)
            .with_body(format!(r#"{{"access_token":"arm-at","id_token":"{id_token}","refresh_token":"rt-1","expires_in":3600}}"#))
            .create_async()
            .await;
        (dc, tok)
    }

    #[tokio::test]
    async fn device_login_persists_refresh_token_and_returns_identity() {
        let mut server = mockito::Server::new_async().await;
        let _mocks = mock_device_login(&mut server).await;
        let store = Arc::new(MemoryStore::new());
        let s = session(&server, store.clone());
        let mut prompted = false;
        let sign_in = s
            .login_device_code("organizations", |_| prompted = true)
            .await
            .unwrap();
        assert!(prompted);
        assert_eq!(sign_in.id, "oid-1");
        assert_eq!(sign_in.tenant_id, "tenant-1");
        assert_eq!(sign_in.user_principal, "a@x.io");
        assert!(
            store
                .get("test:entra:oid-1")
                .unwrap()
                .unwrap()
                .expose_secret()
                .contains("rt-1")
        );
        assert!(s.is_signed_in(&sign_in).unwrap());
    }

    #[tokio::test]
    async fn token_for_refreshes_once_then_serves_from_cache() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let refresh = server
            .mock("POST", "/tenant-1/oauth2/v2.0/token")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
                Matcher::UrlEncoded(
                    "scope".into(),
                    "https://servicebus.azure.net/.default offline_access".into(),
                ),
            ]))
            .with_status(200)
            .with_body(r#"{"access_token":"sb-at","refresh_token":"rt-2","expires_in":3600}"#)
            .expect(1)
            .create_async()
            .await;
        let store = Arc::new(MemoryStore::new());
        let s = session(&server, store.clone());
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        let a = s
            .token_for(&sign_in, None, "https://servicebus.azure.net/.default")
            .await
            .unwrap();
        let b = s
            .token_for(&sign_in, None, "https://servicebus.azure.net/.default")
            .await
            .unwrap();
        assert_eq!(a.token.expose_secret(), "sb-at");
        assert_eq!(b.token.expose_secret(), "sb-at");
        refresh.assert_async().await;
        assert!(
            store
                .get("test:entra:oid-1")
                .unwrap()
                .unwrap()
                .expose_secret()
                .contains("rt-2")
        );
    }

    #[tokio::test]
    async fn token_for_after_revocation_reports_not_signed_in() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let _refresh = server
            .mock("POST", "/tenant-1/oauth2/v2.0/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant","error_description":"AADSTS50173: The provided grant has expired due to it being revoked."}"#)
            .create_async()
            .await;
        let s = session(&server, Arc::new(MemoryStore::new()));
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        let err = s.token_for(&sign_in, None, "scope").await.unwrap_err();
        assert!(
            matches!(&err, KitError::NotSignedIn(m) if m.contains("a@x.io")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn unknown_sign_in_is_not_signed_in() {
        let server = mockito::Server::new_async().await;
        let s = session(&server, Arc::new(MemoryStore::new()));
        let ghost = SignIn {
            id: "ghost".into(),
            user_principal: "g@x.io".into(),
            tenant_id: "t".into(),
            display_name: None,
            cloud: AzureCloud::Public,
        };
        assert!(matches!(
            s.token_for(&ghost, None, "s").await.unwrap_err(),
            KitError::NotSignedIn(_)
        ));
    }

    #[tokio::test]
    async fn logout_forgets_refresh_token() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let store = Arc::new(MemoryStore::new());
        let s = session(&server, store.clone());
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        s.logout(&sign_in).unwrap();
        assert!(!s.is_signed_in(&sign_in).unwrap());
    }

    #[tokio::test]
    async fn logout_during_in_flight_refresh_wins() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let _refresh = server
            .mock("POST", "/tenant-1/oauth2/v2.0/token")
            .with_body_from_request(|_| {
                std::thread::sleep(Duration::from_millis(300));
                br#"{"access_token":"sb-at","refresh_token":"rt-2","expires_in":3600}"#.to_vec()
            })
            .create_async()
            .await;
        let store = Arc::new(MemoryStore::new());
        let s = session(&server, store.clone());
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        let scope = "https://servicebus.azure.net/.default";
        let (res, ()) = tokio::join!(s.token_for(&sign_in, None, scope), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            s.logout(&sign_in).unwrap();
        });
        assert!(
            matches!(&res, Err(KitError::NotSignedIn(m)) if m.contains("signed out")),
            "{res:?}"
        );
        assert!(!s.is_signed_in(&sign_in).unwrap());
        assert!(store.get("test:entra:oid-1").unwrap().is_none());
        assert!(s.token_for(&sign_in, None, scope).await.is_err());
    }

    #[tokio::test]
    async fn invalid_grant_on_home_tenant_forgets_sign_in() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let revoked = r#"{"error":"invalid_grant","error_description":"AADSTS50173: revoked."}"#;
        let _home = server
            .mock("POST", "/tenant-1/oauth2/v2.0/token")
            .with_status(400)
            .with_body(revoked)
            .create_async()
            .await;
        let _other = server
            .mock("POST", "/tenant-2/oauth2/v2.0/token")
            .with_status(400)
            .with_body(revoked)
            .create_async()
            .await;
        let s = session(&server, Arc::new(MemoryStore::new()));
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        // A failure in another tenant must not forget the home sign-in.
        let err = s
            .token_for(&sign_in, Some("tenant-2"), "scope")
            .await
            .unwrap_err();
        assert!(matches!(err, KitError::NotSignedIn(_)), "{err}");
        assert!(s.is_signed_in(&sign_in).unwrap());
        // The home tenant failing does.
        let err = s.token_for(&sign_in, None, "scope").await.unwrap_err();
        assert!(matches!(err, KitError::NotSignedIn(_)), "{err}");
        assert!(!s.is_signed_in(&sign_in).unwrap());
    }

    #[tokio::test]
    async fn client_id_mismatch_is_not_signed_in_without_refresh() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let refresh = server
            .mock("POST", "/tenant-1/oauth2/v2.0/token")
            .expect(0)
            .create_async()
            .await;
        let store = Arc::new(MemoryStore::new());
        let s = session(&server, store.clone());
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        let other = EntraSession::new(AzureCloud::Public, store.clone(), "test")
            .with_oauth(OAuthClient::new(server.url(), "other-cid"));
        let err = other.token_for(&sign_in, None, "scope").await.unwrap_err();
        assert!(
            matches!(&err, KitError::NotSignedIn(m) if m.contains("different client")),
            "{err}"
        );
        refresh.assert_async().await;
    }

    #[tokio::test]
    async fn cross_tenant_refresh_does_not_replace_home_refresh_token() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let _guest = server
            .mock("POST", "/tenant-2/oauth2/v2.0/token")
            .with_status(200)
            .with_body(
                r#"{"access_token":"guest-at","refresh_token":"rt-guest","expires_in":3600}"#,
            )
            .create_async()
            .await;
        let store = Arc::new(MemoryStore::new());
        let s = session(&server, store.clone());
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        let t = s
            .token_for(&sign_in, Some("tenant-2"), "scope")
            .await
            .unwrap();
        assert_eq!(t.token.expose_secret(), "guest-at");
        let stored = store.get("test:entra:oid-1").unwrap().unwrap();
        assert!(
            stored.expose_secret().contains("rt-1"),
            "home refresh token must be kept"
        );
        assert!(!stored.expose_secret().contains("rt-guest"));
    }

    #[tokio::test]
    async fn fresh_login_survives_an_in_flight_revocation() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_device_login(&mut server).await;
        let _slow_revoked = server
            .mock("POST", "/tenant-1/oauth2/v2.0/token")
            .with_status(400)
            .with_body_from_request(|_| {
                std::thread::sleep(std::time::Duration::from_millis(400));
                br#"{"error":"invalid_grant","error_description":"AADSTS50173: revoked"}"#.to_vec()
            })
            .create_async()
            .await;
        let store = Arc::new(MemoryStore::new());
        let s = Arc::new(session(&server, store.clone()));
        let sign_in = s.login_device_code("organizations", |_| {}).await.unwrap();
        let s2 = s.clone();
        let si2 = sign_in.clone();
        let refresh = tokio::spawn(async move { s2.token_for(&si2, None, "scope").await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // The user signs in again while the doomed refresh is still in flight.
        // `finish_login` is called directly: the mock server blocks while it
        // sleeps, so a second HTTP sign-in would only run after the refresh failed.
        let id_token = test_jwt(
            r#"{"tid":"tenant-1","oid":"oid-1","preferred_username":"a@x.io","name":"A"}"#,
        );
        s.finish_login(
            "organizations",
            TokenResponse {
                access_token: "arm-at".into(),
                id_token: Some(id_token),
                refresh_token: Some("rt-fresh".into()),
                expires_in: 3600,
                scope: None,
            },
        )
        .unwrap();
        assert!(refresh.await.unwrap().is_err());
        assert!(
            s.is_signed_in(&sign_in).unwrap(),
            "fresh login must not be deleted"
        );
    }
}
