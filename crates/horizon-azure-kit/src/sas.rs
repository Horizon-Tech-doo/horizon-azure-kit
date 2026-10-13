//! Shared Access Signature (SAS) tokens for Service Bus / Event Hubs style
//! resources. The key is used as raw UTF-8 bytes (NOT base64-decoded).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::Sha256;
use time::OffsetDateTime;

/// RFC 3986 unreserved characters stay literal; everything else is encoded.
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Sign `audience` and return the complete `SharedAccessSignature ...` string.
pub fn sign_sas(audience: &str, key_name: &str, key: &str, expiry_unix: i64) -> String {
    let resource = utf8_percent_encode(audience, ENCODE_SET)
        .to_string()
        .to_lowercase();
    let string_to_sign = format!("{resource}\n{expiry_unix}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    let signature = utf8_percent_encode(&signature, ENCODE_SET);
    let key_name = utf8_percent_encode(key_name, ENCODE_SET);
    format!("SharedAccessSignature sr={resource}&sig={signature}&se={expiry_unix}&skn={key_name}")
}

/// Sign `audience` valid for `ttl` from now. Returns the token and its expiry.
pub fn sas_token(
    audience: &str,
    key_name: &str,
    key: &str,
    ttl: std::time::Duration,
) -> (String, OffsetDateTime) {
    let expires = OffsetDateTime::now_utc() + ttl;
    (
        sign_sas(audience, key_name, key, expires.unix_timestamp()),
        expires,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_vector() {
        let token = sign_sas(
            "https://myns.servicebus.windows.net/myqueue",
            "RootManageSharedAccessKey",
            "abc123=",
            1_700_000_000,
        );
        assert_eq!(
            token,
            "SharedAccessSignature sr=https%3a%2f%2fmyns.servicebus.windows.net%2fmyqueue&sig=6GlxVMpuwouj5YRodkN6TCe9lcUQs5VVsBX42Q0th90%3D&se=1700000000&skn=RootManageSharedAccessKey"
        );
    }

    #[test]
    fn sas_token_expiry_is_in_the_future() {
        let (token, expires) = sas_token(
            "amqp://localhost/orders",
            "k",
            "SAS_KEY_VALUE",
            std::time::Duration::from_secs(3600),
        );
        assert!(token.starts_with("SharedAccessSignature sr=amqp%3a%2f%2flocalhost%2forders&sig="));
        assert!(expires > OffsetDateTime::now_utc());
    }
}
