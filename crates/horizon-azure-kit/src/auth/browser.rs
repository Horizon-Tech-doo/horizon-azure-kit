//! Interactive browser sign-in: authorization code + PKCE over a loopback redirect.

use crate::{KitError, KitResult};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SUCCESS_HTML: &str = "<!doctype html><title>Signed in</title><p>Signed in. You can close this window and return to the app.</p>";
const FAILURE_HTML: &str = "<!doctype html><title>Sign-in failed</title><p>Sign-in failed. Return to the app for details.</p>";

/// A PKCE verifier/challenge pair (RFC 7636, S256).
#[derive(Debug, Clone)]
pub struct Pkce {
    /// High-entropy secret sent with the code exchange.
    pub verifier: String,
    /// `BASE64URL(SHA256(verifier))`, sent with the authorize request.
    pub challenge: String,
}

impl Pkce {
    /// Generate a fresh pair (64-character verifier).
    pub fn generate() -> Self {
        let verifier = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

/// A one-shot HTTP listener on 127.0.0.1 that receives the OAuth redirect.
pub struct LoopbackRedirect {
    listener: TcpListener,
    port: u16,
}

impl LoopbackRedirect {
    /// Bind an ephemeral port on the loopback interface.
    pub async fn bind() -> KitResult<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| KitError::AuthFailed(format!("cannot open loopback listener: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| KitError::AuthFailed(format!("loopback address: {e}")))?
            .port();
        Ok(Self { listener, port })
    }

    /// Redirect URI to register in the authorize request.
    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    /// Wait for the browser to hit the redirect URI and return the `code`.
    /// Requests without a `code` (e.g. `/favicon.ico`) are answered 404 and ignored.
    pub async fn wait_for_code(self, expected_state: &str, timeout: Duration) -> KitResult<String> {
        let wait = async {
            loop {
                let (mut stream, _) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|e| KitError::AuthFailed(format!("loopback accept: {e}")))?;
                let request = read_request_head(&mut stream).await?;
                match parse_redirect(&request, expected_state) {
                    Ok(Some(code)) => {
                        respond(&mut stream, "200 OK", SUCCESS_HTML).await;
                        return Ok(code);
                    }
                    Ok(None) => respond(&mut stream, "404 Not Found", "").await,
                    Err(e) => {
                        respond(&mut stream, "400 Bad Request", FAILURE_HTML).await;
                        return Err(e);
                    }
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| KitError::AuthFailed("browser sign-in timed out".into()))?
    }
}

async fn read_request_head(stream: &mut TcpStream) -> KitResult<String> {
    let mut buf = vec![0u8; 16 * 1024];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| KitError::AuthFailed(format!("loopback read: {e}")))?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Parse the request line of a redirect. `Ok(None)` means "not the redirect".
pub(crate) fn parse_redirect(request: &str, expected_state: &str) -> KitResult<Option<String>> {
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| KitError::AuthFailed("malformed redirect request".into()))?;
    let url = url::Url::parse(&format!("http://localhost{target}"))
        .map_err(|e| KitError::AuthFailed(format!("malformed redirect URL: {e}")))?;
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if let Some(error) = params.get("error") {
        let desc = params.get("error_description").cloned().unwrap_or_default();
        return Err(KitError::AuthFailed(format!("{error}: {desc}")));
    }
    let Some(code) = params.get("code") else {
        return Ok(None);
    };
    if params.get("state").map(String::as_str) != Some(expected_state) {
        return Err(KitError::AuthFailed(
            "state mismatch in sign-in redirect".into(),
        ));
    }
    Ok(Some(code.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let p = Pkce::generate();
        assert_eq!(p.verifier.len(), 64);
        assert_eq!(
            p.challenge,
            URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()))
        );
    }

    #[test]
    fn parses_code_with_matching_state() {
        let req = "GET /?code=abc&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_redirect(req, "xyz").unwrap().as_deref(), Some("abc"));
    }

    #[test]
    fn rejects_state_mismatch() {
        let req = "GET /?code=abc&state=evil HTTP/1.1\r\n\r\n";
        assert!(parse_redirect(req, "xyz").is_err());
    }

    #[test]
    fn surfaces_entra_error() {
        let req = "GET /?error=access_denied&error_description=User+cancelled HTTP/1.1\r\n\r\n";
        let err = parse_redirect(req, "xyz").unwrap_err();
        assert!(err.to_string().contains("User cancelled"));
    }

    #[test]
    fn ignores_favicon() {
        assert!(
            parse_redirect("GET /favicon.ico HTTP/1.1\r\n\r\n", "x")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn listener_returns_code_from_real_request() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let uri = redirect.redirect_uri();
        let port: u16 = uri.rsplit(':').next().unwrap().parse().unwrap();
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        let mut favicon = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        favicon
            .write_all(b"GET /favicon.ico HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut ok = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        ok.write_all(b"GET /?code=the-code&state=s1 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap(), "the-code");
    }
}
