//! Microsoft Entra ID sign-in and token exchange.

mod browser;
mod oauth;

pub use browser::{LoopbackRedirect, Pkce};
pub use oauth::{DeviceCodeResponse, OAuthClient, TokenResponse};
