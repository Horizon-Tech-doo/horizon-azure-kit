//! Minimal Azure Resource Manager client for discovery (read-only).

use crate::{AzureCloud, KitError, KitResult};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::time::Duration;

const TENANTS_API: &str = "2022-12-01";
const SUBSCRIPTIONS_API: &str = "2022-12-01";

/// A tenant the signed-in identity can access.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    /// Tenant GUID.
    pub tenant_id: String,
    /// Display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Primary domain, e.g. `contoso.onmicrosoft.com`.
    #[serde(default)]
    pub default_domain: Option<String>,
}

/// A subscription visible to the token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    /// Subscription GUID.
    pub subscription_id: String,
    /// Display name.
    pub display_name: String,
    /// Owning tenant.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// `Enabled`, `Disabled`, `Warned`, ...
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Deserialize)]
struct Page<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
    #[serde(rename = "nextLink", default)]
    next_link: Option<String>,
}

/// Read-only ARM client bound to one access token.
pub struct ArmClient {
    http: reqwest::Client,
    base: String,
    token: SecretString,
}

impl ArmClient {
    /// Client for `cloud`'s ARM endpoint.
    pub fn new(cloud: AzureCloud, token: SecretString) -> Self {
        Self::with_base(cloud.arm_endpoint(), token)
    }

    /// Client for a custom base URL (tests, Azure Stack).
    pub fn with_base(base: impl Into<String>, token: SecretString) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client builds");
        Self {
            http,
            base: base.into().trim_end_matches('/').to_string(),
            token,
        }
    }

    /// Tenants the identity belongs to.
    pub async fn list_tenants(&self) -> KitResult<Vec<Tenant>> {
        self.get_paged(format!("{}/tenants?api-version={TENANTS_API}", self.base))
            .await
    }

    /// Subscriptions visible to the token.
    pub async fn list_subscriptions(&self) -> KitResult<Vec<Subscription>> {
        self.get_paged(format!(
            "{}/subscriptions?api-version={SUBSCRIPTIONS_API}",
            self.base
        ))
        .await
    }

    /// All resources of `resource_type` (e.g. `Microsoft.ServiceBus/namespaces`)
    /// in a subscription, deserialized as `T`.
    pub async fn list_by_provider<T: DeserializeOwned>(
        &self,
        subscription_id: &str,
        resource_type: &str,
        api_version: &str,
    ) -> KitResult<Vec<T>> {
        self.get_paged(format!(
            "{}/subscriptions/{subscription_id}/providers/{resource_type}?api-version={api_version}",
            self.base
        ))
        .await
    }

    async fn get_paged<T: DeserializeOwned>(&self, first: String) -> KitResult<Vec<T>> {
        let mut out = Vec::new();
        let mut next = Some(first);
        while let Some(url) = next {
            let page: Page<T> = self.get_json(&url).await?;
            out.extend(page.value);
            next = page.next_link;
        }
        Ok(out)
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> KitResult<T> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            .map_err(KitError::network)?;
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(KitError::network)?;
        match status {
            200..=299 => serde_json::from_str(&body).map_err(|e| KitError::Remote {
                status,
                body: format!("ARM decode error: {e}"),
            }),
            401 => Err(KitError::NotSignedIn(format!(
                "ARM rejected the token: {body}"
            ))),
            403 => Err(KitError::Forbidden(body)),
            404 => Err(KitError::NotFound(url.to_string())),
            _ => Err(KitError::Remote { status, body }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Matcher;

    #[tokio::test]
    async fn subscriptions_follow_next_link() {
        let mut server = mockito::Server::new_async().await;
        let next = format!(
            "{}/subscriptions?api-version=2022-12-01&page=2",
            server.url()
        );
        let _p1 = server
            .mock("GET", "/subscriptions")
            .match_query(Matcher::UrlEncoded("api-version".into(), "2022-12-01".into()))
            .match_header("authorization", "Bearer tok")
            .with_status(200)
            .with_body(format!(r#"{{"value":[{{"subscriptionId":"s1","displayName":"One","tenantId":"t"}}],"nextLink":"{next}"}}"#))
            .create_async()
            .await;
        let _p2 = server
            .mock("GET", "/subscriptions")
            .match_query(Matcher::UrlEncoded("page".into(), "2".into()))
            .with_status(200)
            .with_body(r#"{"value":[{"subscriptionId":"s2","displayName":"Two"}]}"#)
            .create_async()
            .await;
        let arm = ArmClient::with_base(server.url(), SecretString::from("tok"));
        let subs = arm.list_subscriptions().await.unwrap();
        assert_eq!(
            subs.iter()
                .map(|s| s.subscription_id.as_str())
                .collect::<Vec<_>>(),
            ["s1", "s2"]
        );
    }

    #[derive(Debug, Deserialize)]
    struct Ns {
        name: String,
    }

    #[tokio::test]
    async fn list_by_provider_builds_path() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                "/subscriptions/s1/providers/Microsoft.ServiceBus/namespaces",
            )
            .match_query(Matcher::UrlEncoded(
                "api-version".into(),
                "2024-01-01".into(),
            ))
            .with_status(200)
            .with_body(r#"{"value":[{"name":"sb1"}]}"#)
            .create_async()
            .await;
        let arm = ArmClient::with_base(server.url(), SecretString::from("tok"));
        let got: Vec<Ns> = arm
            .list_by_provider("s1", "Microsoft.ServiceBus/namespaces", "2024-01-01")
            .await
            .unwrap();
        assert_eq!(got[0].name, "sb1");
    }

    #[tokio::test]
    async fn forbidden_maps_to_forbidden() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/tenants")
            .match_query(Matcher::Any)
            .with_status(403)
            .with_body("AuthorizationFailed")
            .create_async()
            .await;
        let arm = ArmClient::with_base(server.url(), SecretString::from("tok"));
        assert!(matches!(
            arm.list_tenants().await.unwrap_err(),
            KitError::Forbidden(_)
        ));
    }
}
