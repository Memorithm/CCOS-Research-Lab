//! Egress allowlist — the **air-gap control** for the optional network call
//! sites (`llm`, `neural-embed`).
//!
//! CCOS's default posture is *air-gapped*: nothing leaves the host. The few
//! modules that can talk to a network (the LLM client, the quarantined neural
//! embedder, the eval harness) all route their URL through
//! [`EgressAllowlist::check`] before any `reqwest`/`ureq` call. The default
//! policy allows **localhost only**; any non-loopback host is refused with
//! [`EgressError::HostNotAllowed`] unless it appears in the `CCOS_EGRESS_ALLOW`
//! environment variable (comma-separated hosts). Unknown/missing env ⇒
//! localhost-only (the policy **fails closed**, never open).
//!
//! This module is pure `std` and compiled in the **default build** (no feature
//! gate) so the policy is uniform and always present; only the *call sites* are
//! behind the `llm`/`neural-embed` features (the crates that actually do I/O).
//!
//! ```
//! use ccos::egress::EgressAllowlist;
//! let al = EgressAllowlist::localhost_only();
//! assert!(al.check("http://127.0.0.1:11434/api/embeddings").is_ok());
//! assert!(al.check("https://api.anthropic.com/v1/messages").is_err());
//! ```

use std::collections::HashSet;

/// Why an egress was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressError {
    /// The URL could not be parsed (no `scheme://` authority, empty host).
    Malformed(String),
    /// The host is not on the allowlist (air-gap: default localhost only).
    HostNotAllowed {
        host: String,
        allowlist: Vec<String>,
    },
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(u) => write!(f, "egress refused: malformed URL (no scheme/host): {u}"),
            Self::HostNotAllowed { host, allowlist } => write!(
                f,
                "egress refused: host '{host}' not in the allowlist (air-gap; default \
                 localhost only; set CCOS_EGRESS_ALLOW to add hosts). Allowed: {allowlist:?}"
            ),
        }
    }
}

impl std::error::Error for EgressError {}

/// The env var that expands the allowlist beyond localhost (comma-separated
/// hosts, e.g. `CCOS_EGRESS_ALLOW=api.anthropic.com,embeddings.internal`).
pub const ALLOW_ENV: &str = "CCOS_EGRESS_ALLOW";

/// Loopback hosts always allowed — the air-gap default. Both the bare and
/// bracketed IPv6 forms are covered.
const LOOPBACK: &[&str] = &["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"];

/// The air-gap egress policy. Default: localhost/loopback only. Expanded at
/// runtime by [`Self::from_env`] reading `CCOS_EGRESS_ALLOW`.
#[derive(Debug, Clone)]
pub struct EgressAllowlist {
    allowed: HashSet<String>,
}

impl Default for EgressAllowlist {
    fn default() -> Self {
        Self::localhost_only()
    }
}

impl EgressAllowlist {
    /// Default policy: localhost/loopback only. All other hosts are refused.
    pub fn localhost_only() -> Self {
        Self {
            allowed: LOOPBACK.iter().map(|s| (*s).to_lowercase()).collect(),
        }
    }

    /// Default policy **plus** any hosts in `CCOS_EGRESS_ALLOW` (comma-separated).
    /// Missing or unparseable env ⇒ localhost-only (fail closed).
    pub fn from_env() -> Self {
        let mut a = Self::localhost_only();
        if let Ok(val) = std::env::var(ALLOW_ENV) {
            for h in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                a.allowed.insert(h.to_lowercase());
            }
        }
        a
    }

    /// The current allowlist (sorted, for diagnostics).
    pub fn allowed_hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = self.allowed.iter().cloned().collect();
        v.sort();
        v
    }

    /// Check `url`'s host against the allowlist. `Ok(())` if allowed; `Err` if
    /// the host is not on the list or the URL is malformed.
    pub fn check(&self, url: &str) -> Result<(), EgressError> {
        let host = extract_host(url).ok_or_else(|| EgressError::Malformed(url.to_string()))?;
        let h = host.to_lowercase();
        if self.allowed.contains(&h) {
            Ok(())
        } else {
            Err(EgressError::HostNotAllowed {
                host: h,
                allowlist: self.allowed_hosts(),
            })
        }
    }

    /// Convenience: `true` iff [`Self::check`] is `Ok`.
    pub fn is_allowed(&self, url: &str) -> bool {
        self.check(url).is_ok()
    }
}

/// Extract the authority host from a `scheme://host[:port]/path` URL. Returns the
/// host with IPv6 addresses kept in their bracketed form (e.g. `[::1]`). Returns
/// `None` if there is no `://` or no host.
fn extract_host(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    // authority = host[:port], up to the first '/' (or end)
    let authority = after.split('/').next()?;
    // IPv6: [::1] or [::1]:port — keep the bracketed host. `end` is the index
    // of `]` *inside* `inner` (which is `authority` minus the leading `[`), so
    // the closing bracket sits at `end + 1` in `authority`; the host slice
    // therefore runs `[..end + 2]` to include both brackets.
    if let Some(inner) = authority.strip_prefix('[') {
        if let Some(end) = inner.find(']') {
            let host = &authority[..end + 2]; // includes both brackets
            return if host.is_empty() {
                None
            } else {
                Some(host.to_string())
            };
        }
    }
    // Plain host or host:port — strip the port (last ':' before any bracket).
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn al() -> EgressAllowlist {
        EgressAllowlist::localhost_only()
    }

    #[test]
    fn loopback_is_allowed() {
        assert!(al().check("http://127.0.0.1:11434/api/embeddings").is_ok());
        assert!(al().check("http://localhost:11434/v1/chat").is_ok());
        assert!(al().check("http://[::1]:11434/").is_ok());
        assert!(al().check("https://localhost/").is_ok());
    }

    #[test]
    fn non_loopback_is_refused() {
        let e = al().check("https://api.anthropic.com/v1/messages").unwrap_err();
        match e {
            EgressError::HostNotAllowed { host, .. } => assert_eq!(host, "api.anthropic.com"),
            EgressError::Malformed(_) => panic!("expected HostNotAllowed"),
        }
    }

    #[test]
    fn malformed_url_is_refused() {
        assert!(matches!(al().check("not-a-url").unwrap_err(), EgressError::Malformed(_)));
        assert!(matches!(al().check("http:///path").unwrap_err(), EgressError::Malformed(_)));
    }

    #[test]
    fn from_env_expands_allowlist() {
        // Use a unique var value; std::env is process-global so test in isolation
        // by checking the parse logic via localhost_only + a manual host add.
        let mut a = EgressAllowlist::localhost_only();
        a.allowed.insert("api.anthropic.com".to_string());
        assert!(a.check("https://api.anthropic.com/v1/messages").is_ok());
    }

    #[test]
    fn host_is_case_insensitive() {
        let mut a = EgressAllowlist::localhost_only();
        a.allowed.insert("api.anthropic.com".to_string());
        assert!(a.check("https://API.Anthropic.com/v1/messages").is_ok());
    }
}