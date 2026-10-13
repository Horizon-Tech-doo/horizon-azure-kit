//! Identity claims from an Entra JWT. The signature is NOT verified: this only
//! labels a sign-in with names the authority just issued to us. Never use it
//! for authorization decisions.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

/// Best-effort identity fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdentityClaims {
    /// `tid`
    pub tenant_id: Option<String>,
    /// `preferred_username`, else `upn`, `unique_name`, `email`.
    pub user_principal: Option<String>,
    /// `oid` — stable per user per tenant.
    pub object_id: Option<String>,
    /// `name`
    pub name: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawClaims {
    tid: Option<String>,
    oid: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    upn: Option<String>,
    unique_name: Option<String>,
    email: Option<String>,
}

/// Decode the payload segment of a JWT. Malformed input yields defaults.
pub fn parse_identity_claims(jwt: &str) -> IdentityClaims {
    let Some(payload) = jwt.split('.').nth(1) else {
        return IdentityClaims::default();
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')) else {
        return IdentityClaims::default();
    };
    let Ok(raw) = serde_json::from_slice::<RawClaims>(&bytes) else {
        return IdentityClaims::default();
    };
    IdentityClaims {
        tenant_id: raw.tid,
        user_principal: raw
            .preferred_username
            .or(raw.upn)
            .or(raw.unique_name)
            .or(raw.email),
        object_id: raw.oid,
        name: raw.name,
    }
}

#[cfg(test)]
pub(crate) fn test_jwt(payload_json: &str) -> String {
    format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload_json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_preferred_username_tenant_and_oid() {
        let c = parse_identity_claims(&test_jwt(
            r#"{"tid":"t1","oid":"o1","preferred_username":"a@x.io","name":"A"}"#,
        ));
        assert_eq!(c.tenant_id.as_deref(), Some("t1"));
        assert_eq!(c.object_id.as_deref(), Some("o1"));
        assert_eq!(c.user_principal.as_deref(), Some("a@x.io"));
    }

    #[test]
    fn falls_back_to_upn() {
        let c = parse_identity_claims(&test_jwt(r#"{"upn":"u@x.io"}"#));
        assert_eq!(c.user_principal.as_deref(), Some("u@x.io"));
    }

    #[test]
    fn malformed_yields_defaults() {
        assert_eq!(parse_identity_claims("nope"), IdentityClaims::default());
        assert_eq!(parse_identity_claims("a.!!!.c"), IdentityClaims::default());
    }
}
