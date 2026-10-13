//! Azure cloud endpoints.

use serde::{Deserialize, Serialize};

/// The Azure cloud a sign-in or resource belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AzureCloud {
    /// Azure public cloud.
    #[default]
    Public,
    /// Azure operated by 21Vianet (China).
    China,
    /// Azure US Government.
    UsGov,
}

impl AzureCloud {
    /// Microsoft Entra authority host, without trailing slash.
    pub fn authority_host(self) -> &'static str {
        match self {
            AzureCloud::Public => "https://login.microsoftonline.com",
            AzureCloud::China => "https://login.chinacloudapi.cn",
            AzureCloud::UsGov => "https://login.microsoftonline.us",
        }
    }

    /// Azure Resource Manager endpoint, without trailing slash.
    pub fn arm_endpoint(self) -> &'static str {
        match self {
            AzureCloud::Public => "https://management.azure.com",
            AzureCloud::China => "https://management.chinacloudapi.cn",
            AzureCloud::UsGov => "https://management.usgovcloudapi.net",
        }
    }

    /// OAuth scope for ARM access tokens.
    pub fn arm_scope(self) -> String {
        format!("{}/.default", self.arm_endpoint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_cloud_endpoints() {
        let c = AzureCloud::Public;
        assert_eq!(c.authority_host(), "https://login.microsoftonline.com");
        assert_eq!(c.arm_scope(), "https://management.azure.com/.default");
    }

    #[test]
    fn sovereign_clouds_differ() {
        assert_ne!(
            AzureCloud::China.arm_endpoint(),
            AzureCloud::Public.arm_endpoint()
        );
        assert_eq!(
            AzureCloud::UsGov.authority_host(),
            "https://login.microsoftonline.us"
        );
    }

    #[test]
    fn serde_names_are_kebab_case() {
        assert_eq!(
            serde_json::to_string(&AzureCloud::UsGov).unwrap(),
            "\"us-gov\""
        );
    }
}
