# horizon-azure-kit

Shared Azure plumbing for Horizon Tech's desktop tools. Used by [Dispatched](https://github.com/Horizon-Tech-doo/dispatched); [Arkived](https://github.com/Horizon-Tech-doo/arkived) will migrate to it.

- `auth` — Microsoft Entra sign-in (browser + PKCE, device code), refresh-token cache, per-scope token exchange
- `secrets` — OS keychain credential store (chunked for large tokens) + in-memory store
- `arm` — Azure Resource Manager discovery (tenants, subscriptions, resources by provider)
- `sas` — Shared Access Signature signing
- `safety` — confirmation policy for destructive operations, cancellation

Only code that more than one product needs lives here. Product domain logic does not.

Not affiliated with Microsoft. "Azure" and "Microsoft Entra" are trademarks of Microsoft Corporation.

Licensed under Apache-2.0.

## Changes

- **0.2.1**: the shared Tauri release workflow signs and notarizes macOS builds when the caller repo sets the `APPLE_*` secrets; without them builds stay unsigned. No crate changes.
- **0.2.0**
  - `EntraSession::token_for` no longer replaces the stored (home-tenant) refresh token after refreshing against another tenant.
  - Signing in again wins over a refresh that is still in flight.
- **0.1.0**: initial release (Dispatched M0).
