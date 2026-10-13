//! Microsoft Entra ID sign-in and token exchange.

mod oauth;

pub use oauth::{DeviceCodeResponse, OAuthClient, TokenResponse};
