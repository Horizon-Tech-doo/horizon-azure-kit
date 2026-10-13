# horizon-azure-kit

Shared Azure plumbing for Horizon Tech's desktop tools ([Arkived](https://github.com/Horizon-Tech-doo/arkived), [Dispatched](https://github.com/Horizon-Tech-doo/dispatched)):

- `auth` — Microsoft Entra sign-in (browser + PKCE, device code), refresh-token cache, per-scope token exchange
- `secrets` — OS keychain credential store (chunked for large tokens) + in-memory store
- `arm` — Azure Resource Manager discovery (tenants, subscriptions, resources by provider)
- `sas` — Shared Access Signature signing
- `safety` — confirmation policy for destructive operations, cancellation

Only code that more than one product needs lives here. Product domain logic does not.

Not affiliated with Microsoft. "Azure" and "Microsoft Entra" are trademarks of Microsoft Corporation.

Licensed under Apache-2.0.
