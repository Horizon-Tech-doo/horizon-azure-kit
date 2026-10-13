//! Interactive browser sign-in: authorization code + PKCE over a loopback redirect.

use crate::{KitError, KitResult};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const SUCCESS_HTML: &str = "<!doctype html><title>Signed in</title><p>Signed in. You can close this window and return to the app.</p>";
const FAILURE_HTML: &str = "<!doctype html><title>Sign-in failed</title><p>Sign-in failed. Return to the app for details.</p>";

/// Maximum bytes read from one connection before the request head is parsed.
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Per-connection budget for receiving the request head.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause after a failed `accept`, so a persistent error does not spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// A PKCE verifier/challenge pair (RFC 7636, S256).
#[derive(Clone)]
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

impl std::fmt::Debug for Pkce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &"<redacted>")
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// A loopback listener on 127.0.0.1 (and [::1] when available, same port)
/// that receives the OAuth redirect.
pub struct LoopbackRedirect {
    v4: TcpListener,
    v6: Option<TcpListener>,
    port: u16,
}

impl LoopbackRedirect {
    /// Bind an ephemeral port on the loopback interface. The IPv6 listener is
    /// best effort: if it cannot be bound, sign-in continues over IPv4 only.
    pub async fn bind() -> KitResult<Self> {
        let v4 = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| KitError::AuthFailed(format!("cannot open loopback listener: {e}")))?;
        let port = v4
            .local_addr()
            .map_err(|e| KitError::AuthFailed(format!("loopback address: {e}")))?
            .port();
        let v6 = TcpListener::bind(("::1", port)).await.ok();
        Ok(Self { v4, v6, port })
    }

    /// Redirect URI to register in the authorize request.
    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    /// Wait for the browser to hit the redirect URI and return the `code`.
    ///
    /// Only a request carrying the expected `state` is authoritative. Anything
    /// else (empty, stalled, malformed, probing requests) is answered and
    /// ignored, and the wait continues until the overall `timeout`.
    pub async fn wait_for_code(self, expected_state: &str, timeout: Duration) -> KitResult<String> {
        let wait = async {
            let (tx, mut rx) = mpsc::unbounded_channel::<KitResult<String>>();
            loop {
                tokio::select! {
                    accepted = self.v4.accept() => match accepted {
                        Ok((stream, _)) => spawn_connection(stream, expected_state, tx.clone()),
                        Err(_) => tokio::time::sleep(ACCEPT_RETRY).await,
                    },
                    accepted = accept_optional(self.v6.as_ref()) => match accepted {
                        Ok((stream, _)) => spawn_connection(stream, expected_state, tx.clone()),
                        Err(_) => tokio::time::sleep(ACCEPT_RETRY).await,
                    },
                    Some(outcome) = rx.recv() => return outcome,
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| KitError::AuthFailed("browser sign-in timed out".into()))?
    }
}

async fn accept_optional(
    listener: Option<&TcpListener>,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

/// Handle one connection on its own task, so a stalled peer cannot delay
/// other connections. Only terminal outcomes are sent to the waiting loop.
fn spawn_connection(
    mut stream: TcpStream,
    expected_state: &str,
    tx: mpsc::UnboundedSender<KitResult<String>>,
) {
    let expected_state = expected_state.to_owned();
    tokio::spawn(async move {
        // A read error or timeout yields an empty head, which parses as
        // `Rejected` and gets a 400 below.
        let head = match tokio::time::timeout(READ_TIMEOUT, read_request_head(&mut stream)).await {
            Ok(Ok(head)) => head,
            _ => String::new(),
        };
        match parse_redirect(&head, &expected_state) {
            Redirect::Code(code) => {
                respond(&mut stream, "200 OK", SUCCESS_HTML).await;
                let _ = tx.send(Ok(code));
            }
            Redirect::Failed(error) => {
                respond(&mut stream, "400 Bad Request", FAILURE_HTML).await;
                let _ = tx.send(Err(error));
            }
            Redirect::NotOurs => respond(&mut stream, "404 Not Found", "").await,
            Redirect::Rejected => respond(&mut stream, "400 Bad Request", "").await,
        }
    });
}

/// Read until the end of the request head (`\r\n\r\n`), EOF, or the size cap.
async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while buf.len() < MAX_REQUEST_BYTES {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    buf.truncate(MAX_REQUEST_BYTES);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Classification of one request received on the loopback listener.
#[derive(Debug)]
pub(crate) enum Redirect {
    /// Matching state and a `code`: sign-in succeeded.
    Code(String),
    /// Matching state and an `error`: the identity provider ended the flow.
    Failed(KitError),
    /// Not the redirect (no state, or no code/error). Answered 404; keep waiting.
    NotOurs,
    /// Wrong state, or an unparsable request. Answered 400; keep waiting.
    Rejected,
}

/// Classify a raw request head. Only a request whose `state` equals
/// `expected_state` can produce `Code` or `Failed`.
pub(crate) fn parse_redirect(request: &str, expected_state: &str) -> Redirect {
    let Some(target) = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
    else {
        return Redirect::Rejected;
    };
    let Ok(url) = url::Url::parse(&format!("http://localhost{target}")) else {
        return Redirect::Rejected;
    };
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    match params.get("state").map(String::as_str) {
        Some(state) if state == expected_state => {}
        Some(_) => return Redirect::Rejected,
        None => return Redirect::NotOurs,
    }
    if let Some(error) = params.get("error") {
        let desc = params.get("error_description").cloned().unwrap_or_default();
        return Redirect::Failed(KitError::AuthFailed(format!("{error}: {desc}")));
    }
    match params.get("code") {
        Some(code) => Redirect::Code(code.clone()),
        None => Redirect::NotOurs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use tokio::io::AsyncReadExt;

    fn port_of(redirect: &LoopbackRedirect) -> u16 {
        redirect
            .redirect_uri()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Send one request and read the full response (the server closes it).
    async fn send_request(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

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
    fn pkce_debug_redacts_verifier() {
        let p = Pkce::generate();
        let shown = format!("{p:?}");
        assert!(!shown.contains(&p.verifier));
        assert!(shown.contains(&p.challenge));
    }

    #[test]
    fn parses_code_with_matching_state() {
        let req = "GET /?code=abc&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(matches!(parse_redirect(req, "xyz"), Redirect::Code(c) if c == "abc"));
    }

    #[test]
    fn wrong_state_is_rejected() {
        let req = "GET /?code=abc&state=evil HTTP/1.1\r\n\r\n";
        assert!(matches!(parse_redirect(req, "xyz"), Redirect::Rejected));
    }

    #[test]
    fn error_with_matching_state_fails_flow() {
        let req =
            "GET /?error=access_denied&error_description=User+cancelled&state=xyz HTTP/1.1\r\n\r\n";
        match parse_redirect(req, "xyz") {
            Redirect::Failed(KitError::AuthFailed(msg)) => {
                assert!(msg.contains("access_denied"));
                assert!(msg.contains("User cancelled"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn error_without_or_with_wrong_state_is_not_authoritative() {
        let missing = "GET /?error=access_denied HTTP/1.1\r\n\r\n";
        assert!(matches!(parse_redirect(missing, "xyz"), Redirect::NotOurs));
        let wrong = "GET /?error=access_denied&state=evil HTTP/1.1\r\n\r\n";
        assert!(matches!(parse_redirect(wrong, "xyz"), Redirect::Rejected));
    }

    #[test]
    fn ignores_favicon() {
        assert!(matches!(
            parse_redirect("GET /favicon.ico HTTP/1.1\r\n\r\n", "x"),
            Redirect::NotOurs
        ));
    }

    #[test]
    fn empty_or_garbage_request_is_rejected() {
        assert!(matches!(parse_redirect("", "x"), Redirect::Rejected));
        assert!(matches!(
            parse_redirect("\r\n\r\n", "x"),
            Redirect::Rejected
        ));
    }

    #[tokio::test]
    async fn listener_returns_code_from_real_request() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        let _ = send_request(port, "GET /favicon.ico HTTP/1.1\r\n\r\n").await;
        let response = send_request(port, "GET /?code=the-code&state=s1 HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(waiter.await.unwrap().unwrap(), "the-code");
    }

    #[tokio::test]
    async fn empty_connection_does_not_abort_sign_in() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        drop(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
        send_request(port, "GET /?code=after-empty&state=s1 HTTP/1.1\r\n\r\n").await;
        assert_eq!(waiter.await.unwrap().unwrap(), "after-empty");
    }

    #[tokio::test]
    async fn stalled_connection_does_not_block_sign_in() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(30)));
        let _stalled = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        send_request(port, "GET /?code=past-stall&state=s1 HTTP/1.1\r\n\r\n").await;
        let code = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .expect("sign-in must not wait for the stalled connection")
            .unwrap();
        assert_eq!(code.unwrap(), "past-stall");
    }

    #[tokio::test]
    async fn wrong_state_code_does_not_abort_sign_in() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        let response = send_request(port, "GET /?code=forged&state=evil HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 400"));
        send_request(port, "GET /?code=real&state=s1 HTTP/1.1\r\n\r\n").await;
        assert_eq!(waiter.await.unwrap().unwrap(), "real");
    }

    #[tokio::test]
    async fn error_without_state_is_ignored() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        let probe = send_request(port, "GET /?error=x HTTP/1.1\r\n\r\n").await;
        assert!(probe.starts_with("HTTP/1.1 404"));
        send_request(port, "GET /?error=x&state=evil HTTP/1.1\r\n\r\n").await;
        send_request(port, "GET /?code=later&state=s1 HTTP/1.1\r\n\r\n").await;
        assert_eq!(waiter.await.unwrap().unwrap(), "later");
    }

    #[tokio::test]
    async fn matching_error_ends_sign_in() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        send_request(port, "GET /?error=access_denied&state=s1 HTTP/1.1\r\n\r\n").await;
        match waiter.await.unwrap() {
            Err(KitError::AuthFailed(msg)) => assert!(msg.contains("access_denied")),
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_split_across_writes_is_parsed() {
        let redirect = LoopbackRedirect::bind().await.unwrap();
        let port = port_of(&redirect);
        let waiter = tokio::spawn(redirect.wait_for_code("s1", Duration::from_secs(5)));
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET /?code=split-code&sta")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.write_all(b"te=s1 HTTP/1.1\r\n\r\n").await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"));
        assert_eq!(waiter.await.unwrap().unwrap(), "split-code");
    }
}
