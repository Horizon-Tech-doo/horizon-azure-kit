//! Microsoft Entra ID sign-in and token exchange.

mod browser;
mod claims;
mod oauth;
mod session;

pub use browser::{LoopbackRedirect, Pkce};
pub use claims::{IdentityClaims, parse_identity_claims};
pub use oauth::{DeviceCodeResponse, OAuthClient, TokenResponse};
pub use session::{AZURE_CLI_CLIENT_ID, AccessToken, EntraSession, SignIn};
