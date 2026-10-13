//! Human-in-the-loop confirmation for destructive operations, and cancellation.
//!
//! Every surface (desktop, CLI, MCP) implements [`Policy`]. Core libraries call
//! [`require`] before any mutating broker or storage call.

use crate::{KitError, KitResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use tokio_util::sync::CancellationToken;

/// Which surface initiated an operation (shown in confirmations and audit logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Desktop app.
    Gui,
    /// Command line.
    Cli,
    /// An agent through MCP.
    Mcp,
}

/// A proposed destructive operation.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmRequest {
    /// Short verb, e.g. `purge`.
    pub verb: String,
    /// Exact target, e.g. `orders/$DeadLetterQueue`.
    pub target: String,
    /// Sentence naming the exact effect, shown to the human.
    pub summary: String,
    /// Number of items affected, if known.
    pub item_count: Option<u64>,
    /// Whether the effect can be undone.
    pub reversible: bool,
    /// The target belongs to a profile marked production.
    pub production: bool,
    /// Who asked.
    pub origin: Origin,
}

impl ConfirmRequest {
    /// Production targets require the human to type the target name
    /// (GUI), pass an explicit flag (CLI), or approve per call (MCP).
    pub fn requires_typed_confirmation(&self) -> bool {
        self.production
    }
}

/// A policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Proceed.
    Allow,
    /// Refuse, with a reason shown to the caller.
    Deny(String),
}

/// Confirmation gate implemented by each surface.
#[async_trait]
pub trait Policy: Send + Sync {
    /// Ask whether `req` may proceed.
    async fn confirm(&self, req: &ConfirmRequest) -> Decision;
}

/// Refuses everything. The safe default.
pub struct DenyAll;

#[async_trait]
impl Policy for DenyAll {
    async fn confirm(&self, req: &ConfirmRequest) -> Decision {
        Decision::Deny(format!(
            "{} on {} is not allowed in this context",
            req.verb, req.target
        ))
    }
}

/// Allows everything. Tests and explicitly trusted automation only; never
/// for agent-facing surfaces.
pub struct AllowAll;

#[async_trait]
impl Policy for AllowAll {
    async fn confirm(&self, _req: &ConfirmRequest) -> Decision {
        Decision::Allow
    }
}

/// Ask `policy` and turn a denial into [`KitError::PolicyDenied`].
pub async fn require(policy: &dyn Policy, req: &ConfirmRequest) -> KitResult<()> {
    match policy.confirm(req).await {
        Decision::Allow => Ok(()),
        Decision::Deny(reason) => Err(KitError::PolicyDenied(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(production: bool) -> ConfirmRequest {
        ConfirmRequest {
            verb: "purge".into(),
            target: "orders/$DeadLetterQueue".into(),
            summary: "Remove 12 messages from orders/$DeadLetterQueue".into(),
            item_count: Some(12),
            reversible: false,
            production,
            origin: Origin::Cli,
        }
    }

    #[tokio::test]
    async fn deny_all_maps_to_policy_denied() {
        let err = require(&DenyAll, &req(false)).await.unwrap_err();
        assert!(matches!(err, KitError::PolicyDenied(m) if m.contains("purge")));
    }

    #[tokio::test]
    async fn allow_all_allows() {
        require(&AllowAll, &req(false)).await.unwrap();
    }

    #[test]
    fn production_requires_typed_confirmation() {
        assert!(req(true).requires_typed_confirmation());
        assert!(!req(false).requires_typed_confirmation());
    }

    #[tokio::test]
    async fn cancellation_token_propagates_to_children() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        parent.cancel();
        child.cancelled().await;
        assert!(child.is_cancelled());
    }
}
