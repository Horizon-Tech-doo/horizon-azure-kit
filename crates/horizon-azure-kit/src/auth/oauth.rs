//! Microsoft Entra OAuth 2.0 endpoints (v2.0).

use crate::{KitError, KitResult};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Bytes escaped in tenant path segments: everything except unreserved `- _ . ~`.
const TENANT_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Maximum characters of a non-JSON error body kept in an error message.
const SNIPPET_MAX_CHARS: usize = 300;

/// First line of an error body, truncated, so that HTML gateway pages do not
/// flood error messages or logs.
fn snippet(body: &str) -> String {
    body.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(SNIPPET_MAX_CHARS)
        .collect()
}

/// Response of the `/devicecode` endpoint.
#[derive(Clone, Deserialize, Serialize)]
pub struct DeviceCodeResponse {
    /// Code the user types at `verification_uri`.
    pub user_code: String,
    /// URL the user opens.
    pub verification_uri: String,
    /// Opaque code used to poll the token endpoint.
    pub device_code: String,
    /// Seconds until the codes expire.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
    /// Ready-to-show instruction text.
    pub message: String,
}

impl std::fmt::Debug for DeviceCodeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCodeResponse")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("device_code", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .field("message", &self.message)
            .finish()
    }
}

/// Successful token-endpoint response.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    /// Bearer access token.
    pub access_token: String,
    /// OpenID id_token when `openid` was requested.
    #[serde(default)]
    pub id_token: Option<String>,
    /// Refresh token when `offline_access` was requested.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// Granted scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct TokenError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Client for one Entra authority host and one public client id.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    authority_host: String,
    client_id: String,
}

impl OAuthClient {
    /// Build a client. `authority_host` is e.g. `https://login.microsoftonline.com`.
    pub fn new(authority_host: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds"),
            authority_host: authority_host.into().trim_end_matches('/').to_string(),
            client_id: client_id.into(),
        }
    }

    /// The public client id in use.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    fn endpoint(&self, tenant: &str, path: &str) -> String {
        let tenant = utf8_percent_encode(tenant, TENANT_ESCAPE);
        format!("{}/{tenant}/oauth2/v2.0/{path}", self.authority_host)
    }

    /// Start a device-code flow.
    pub async fn start_device_code(
        &self,
        tenant: &str,
        scope: &str,
    ) -> KitResult<DeviceCodeResponse> {
        let resp = self
            .http
            .post(self.endpoint(tenant, "devicecode"))
            .form(&[("client_id", self.client_id.as_str()), ("scope", scope)])
            .send()
            .await
            .map_err(KitError::network)?;
        let status = resp.status();
        let body = resp.text().await.map_err(KitError::network)?;
        if !status.is_success() {
            return Err(KitError::AuthFailed(format!(
                "devicecode endpoint returned {status}: {}",
                snippet(&body)
            )));
        }
        serde_json::from_str(&body)
            .map_err(|e| KitError::AuthFailed(format!("devicecode parse: {e}")))
    }

    /// Poll until the user completes the device-code sign-in, it is declined, or it expires.
    pub async fn poll_device_code(
        &self,
        tenant: &str,
        dc: &DeviceCodeResponse,
    ) -> KitResult<TokenResponse> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(dc.expires_in);
        let mut interval = Duration::from_secs(dc.interval.max(1));
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(KitError::AuthFailed("device-code sign-in timed out".into()));
            }
            let form = [
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", self.client_id.as_str()),
                ("device_code", dc.device_code.as_str()),
            ];
            match self.token_request(tenant, &form).await? {
                Ok(token) => return Ok(token),
                Err(err) => match err.error.as_str() {
                    "authorization_pending" => {}
                    "slow_down" => interval += Duration::from_secs(5),
                    _ => return Err(auth_error(err)),
                },
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Exchange a refresh token for an access token for `scope`.
    pub async fn refresh(
        &self,
        tenant: &str,
        refresh_token: &str,
        scope: &str,
    ) -> KitResult<TokenResponse> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("refresh_token", refresh_token),
            ("scope", scope),
        ];
        self.token_request(tenant, &form).await?.map_err(auth_error)
    }

    /// Build the browser authorization URL (authorization code + PKCE S256).
    pub fn authorize_url(
        &self,
        tenant: &str,
        scope: &str,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> String {
        let mut url = url::Url::parse(&self.endpoint(tenant, "authorize"))
            .expect("authority host and tenant form a valid URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_mode", "query")
            .append_pair("scope", scope)
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
        url.into()
    }

    /// Redeem an authorization code obtained through [`OAuthClient::authorize_url`].
    pub async fn exchange_code(
        &self,
        tenant: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
        scope: &str,
    ) -> KitResult<TokenResponse> {
        let form = [
            ("grant_type", "authorization_code"),
            ("client_id", self.client_id.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
            ("scope", scope),
        ];
        self.token_request(tenant, &form).await?.map_err(auth_error)
    }

    async fn token_request(
        &self,
        tenant: &str,
        form: &[(&str, &str)],
    ) -> KitResult<Result<TokenResponse, TokenError>> {
        let resp = self
            .http
            .post(self.endpoint(tenant, "token"))
            .form(form)
            .send()
            .await
            .map_err(KitError::network)?;
        let ok = resp.status().is_success();
        let body = resp.text().await.map_err(KitError::network)?;
        if ok {
            return serde_json::from_str(&body)
                .map(Ok)
                .map_err(|e| KitError::AuthFailed(format!("token parse: {e}")));
        }
        Ok(Err(serde_json::from_str(&body).unwrap_or(TokenError {
            error: "unknown_error".into(),
            error_description: Some(snippet(&body)),
        })))
    }
}

/// Map a token-endpoint error to a kit error. Expired, revoked or
/// MFA/Conditional-Access-blocked sessions become `NotSignedIn` so callers
/// can prompt for an interactive sign-in instead of showing a raw error.
fn auth_error(err: TokenError) -> KitError {
    let desc = err.error_description.unwrap_or_default();
    let needs_interaction = matches!(err.error.as_str(), "invalid_grant" | "interaction_required")
        || ["AADSTS50076", "AADSTS50079", "AADSTS53003", "AADSTS700082"]
            .iter()
            .any(|code| desc.contains(code));
    if needs_interaction {
        let first_line = desc.lines().next().unwrap_or_default().to_string();
        KitError::NotSignedIn(format!("sign in again ({}: {first_line})", err.error))
    } else {
        KitError::AuthFailed(format!("{}: {desc}", err.error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Matcher;

    #[test]
    fn debug_output_redacts_tokens() {
        let token = TokenResponse {
            access_token: "SECRET_ACCESS".into(),
            id_token: Some("SECRET_ID".into()),
            refresh_token: Some("SECRET_REFRESH".into()),
            expires_in: 3600,
            scope: Some("s".into()),
        };
        let dbg = format!("{token:?}");
        assert!(!dbg.contains("SECRET_ACCESS"), "{dbg}");
        assert!(!dbg.contains("SECRET_ID"), "{dbg}");
        assert!(!dbg.contains("SECRET_REFRESH"), "{dbg}");
        assert!(dbg.contains("<redacted>"), "{dbg}");

        let no_optionals = TokenResponse {
            access_token: "SECRET_ACCESS".into(),
            id_token: None,
            refresh_token: None,
            expires_in: 1,
            scope: None,
        };
        let dbg = format!("{no_optionals:?}");
        assert!(dbg.contains("id_token: None"), "{dbg}");
        assert!(dbg.contains("refresh_token: None"), "{dbg}");

        let dc = DeviceCodeResponse {
            user_code: "AB-CD".into(),
            verification_uri: "https://microsoft.com/devicelogin".into(),
            device_code: "SECRET_DEVICE".into(),
            expires_in: 900,
            interval: 5,
            message: "go".into(),
        };
        let dbg = format!("{dc:?}");
        assert!(!dbg.contains("SECRET_DEVICE"), "{dbg}");
        assert!(dbg.contains("AB-CD"), "{dbg}");
    }

    #[test]
    fn snippet_keeps_first_line_and_truncates() {
        assert_eq!(snippet("<html>\n<body>gateway</body>"), "<html>");
        assert_eq!(snippet(""), "");
        let long = "x".repeat(1000);
        assert_eq!(snippet(&long).chars().count(), SNIPPET_MAX_CHARS);
        let multibyte = "é".repeat(500);
        assert_eq!(snippet(&multibyte).chars().count(), SNIPPET_MAX_CHARS);
    }

    #[test]
    fn tenant_is_percent_encoded_in_endpoint() {
        let client = OAuthClient::new("https://login.microsoftonline.com", "cid");
        let url = client.endpoint("a/b?c", "token");
        assert!(!url.contains("/b?"), "{url}");
        assert_eq!(
            url,
            "https://login.microsoftonline.com/a%2Fb%3Fc/oauth2/v2.0/token"
        );
        assert_eq!(
            client.endpoint("contoso.onmicrosoft.com", "token"),
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
        );
    }

    fn token_json() -> &'static str {
        r#"{"access_token":"at","refresh_token":"rt","expires_in":3600,"token_type":"Bearer","scope":"s"}"#
    }

    #[tokio::test]
    async fn device_code_start_parses_response() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/organizations/oauth2/v2.0/devicecode")
            .match_body(Matcher::UrlEncoded("client_id".into(), "cid".into()))
            .with_status(200)
            .with_body(r#"{"user_code":"AB-CD","verification_uri":"https://microsoft.com/devicelogin","device_code":"dc","expires_in":900,"interval":5,"message":"go"}"#)
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        let dc = client
            .start_device_code("organizations", "scope")
            .await
            .unwrap();
        assert_eq!(dc.user_code, "AB-CD");
        assert_eq!(dc.interval, 5);
    }

    #[tokio::test]
    async fn device_code_poll_returns_token_on_success() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/t/oauth2/v2.0/token")
            .match_body(Matcher::UrlEncoded("device_code".into(), "dc".into()))
            .with_status(200)
            .with_body(token_json())
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        let dc = DeviceCodeResponse {
            user_code: "u".into(),
            verification_uri: "v".into(),
            device_code: "dc".into(),
            expires_in: 30,
            interval: 1,
            message: "m".into(),
        };
        let token = client.poll_device_code("t", &dc).await.unwrap();
        assert_eq!(token.access_token, "at");
        assert_eq!(token.refresh_token.as_deref(), Some("rt"));
    }

    #[tokio::test]
    async fn device_code_declined_is_auth_failed() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/t/oauth2/v2.0/token")
            .with_status(400)
            .with_body(r#"{"error":"authorization_declined","error_description":"user said no"}"#)
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        let dc = DeviceCodeResponse {
            user_code: "u".into(),
            verification_uri: "v".into(),
            device_code: "dc".into(),
            expires_in: 30,
            interval: 1,
            message: "m".into(),
        };
        let err = client.poll_device_code("t", &dc).await.unwrap_err();
        assert!(matches!(err, KitError::AuthFailed(m) if m.contains("authorization_declined")));
    }

    #[tokio::test]
    async fn refresh_success() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/t/oauth2/v2.0/token")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
                Matcher::UrlEncoded(
                    "scope".into(),
                    "https://servicebus.azure.net/.default offline_access".into(),
                ),
            ]))
            .with_status(200)
            .with_body(token_json())
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        let t = client
            .refresh(
                "t",
                "rt",
                "https://servicebus.azure.net/.default offline_access",
            )
            .await
            .unwrap();
        assert_eq!(t.access_token, "at");
    }

    #[tokio::test]
    async fn refresh_invalid_grant_is_not_signed_in() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/t/oauth2/v2.0/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant","error_description":"AADSTS700082: The refresh token has expired due to inactivity.\r\nTrace ID: x"}"#)
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        let err = client.refresh("t", "rt", "s").await.unwrap_err();
        assert!(
            matches!(&err, KitError::NotSignedIn(m) if m.contains("AADSTS700082")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn refresh_mfa_required_is_not_signed_in() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/t/oauth2/v2.0/token")
            .with_status(400)
            .with_body(r#"{"error":"interaction_required","error_description":"AADSTS50076: multi-factor authentication required"}"#)
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        assert!(matches!(
            client.refresh("t", "rt", "s").await.unwrap_err(),
            KitError::NotSignedIn(_)
        ));
    }

    #[tokio::test]
    async fn exchange_code_sends_pkce_verifier() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/t/oauth2/v2.0/token")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
                Matcher::UrlEncoded("code_verifier".into(), "verifier".into()),
                Matcher::UrlEncoded("redirect_uri".into(), "http://localhost:5555".into()),
            ]))
            .with_status(200)
            .with_body(token_json())
            .create_async()
            .await;
        let client = OAuthClient::new(server.url(), "cid");
        let t = client
            .exchange_code("t", "code", "http://localhost:5555", "verifier", "s")
            .await
            .unwrap();
        assert_eq!(t.access_token, "at");
    }

    #[test]
    fn authorize_url_carries_pkce_and_state() {
        let client = OAuthClient::new("https://login.microsoftonline.com/", "cid");
        let url = url::Url::parse(&client.authorize_url(
            "organizations",
            "a b",
            "http://localhost:1",
            "st",
            "ch",
        ))
        .unwrap();
        assert_eq!(url.path(), "/organizations/oauth2/v2.0/authorize");
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], "ch");
        assert_eq!(q["state"], "st");
        assert_eq!(q["scope"], "a b");
    }
}
