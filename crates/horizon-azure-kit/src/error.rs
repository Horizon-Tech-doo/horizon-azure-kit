//! Error type shared by every kit module.

/// Result alias for kit operations.
pub type KitResult<T> = Result<T, KitError>;

/// Errors produced by the kit. Products convert these into their own error
/// types with `From`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KitError {
    /// Sign-in or token exchange failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    /// No usable session: never signed in, refresh token expired or revoked,
    /// or the tenant requires interactive sign-in (MFA / Conditional Access).
    #[error("not signed in: {0}")]
    NotSignedIn(String),
    /// A requested resource or secret does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The identity lacks permission.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Transport-level failure (DNS, TLS, connection reset, timeout).
    #[error("network error: {0}")]
    Network(String),
    /// A remote service answered with an unexpected status.
    #[error("unexpected response ({status}): {body}")]
    Remote {
        /// HTTP status code.
        status: u16,
        /// Response body (may be truncated by the caller).
        body: String,
    },
    /// The OS keychain or another secret store failed.
    #[error("secret store error: {0}")]
    SecretStore(String),
    /// A destructive operation was refused by the confirmation policy.
    #[error("operation denied: {0}")]
    PolicyDenied(String),
    /// The operation was cancelled by the caller.
    #[error("cancelled")]
    Cancelled,
    /// The caller passed invalid input.
    #[error("invalid input: {0}")]
    Invalid(String),
}

impl KitError {
    pub(crate) fn network(e: reqwest::Error) -> Self {
        KitError::Network(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_are_actionable() {
        assert_eq!(
            KitError::NotSignedIn("session expired; sign in again".into()).to_string(),
            "not signed in: session expired; sign in again"
        );
        assert_eq!(
            KitError::Remote {
                status: 500,
                body: "boom".into()
            }
            .to_string(),
            "unexpected response (500): boom"
        );
    }
}
