use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;

/// Whether an address binds to *every* interface rather than one specific
/// one.
///
/// NOTE (post-review fix): `is_unspecified()` was the only check here, and
/// on `Ipv6Addr` it is true only for the literal all-zero `::`. An
/// IPv4-mapped address such as `::ffff:0.0.0.0` is a different bit pattern
/// that `is_unspecified()` reports as `false`, yet binding a dual-stack
/// socket to it listens on every IPv4 interface, the public internet
/// included. So `[::ffff:0.0.0.0]:8443` walked straight past the guard that
/// exists precisely to stop that.
///
/// Unmapping and re-testing closes it without over-broadening: a mapped
/// address naming a real interface (`::ffff:192.168.1.1`) unmaps to a
/// specified IPv4 address and stays allowed.
fn is_blanket_public(ip: IpAddr) -> bool {
    if ip.is_unspecified() {
        return true;
    }
    matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified()))
}

pub fn validate_bind_address(addr: &str, allow_public: bool) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("'{addr}' is not a valid socket address (host:port): {e}"))?;
    if is_blanket_public(socket_addr.ip()) && !allow_public {
        anyhow::bail!(
            "refusing to bind to blanket-public address '{addr}'. \
             If you genuinely intend this, pass --allow-public-bind. \
             This tool executes commands on your system; binding it to \
             every interface, including the public internet, is almost \
             never what you want."
        );
    }
    Ok(())
}

/// Compares two credentials without leaking their contents through timing.
///
/// NOTE (post-review fix): this was a hand-rolled XOR-accumulator loop. That
/// shape is a well-known one for LLVM to recognise and lower to a
/// short-circuiting `memcmp` at release optimisation levels, which silently
/// removes the only property the function exists to provide, and it does so
/// without changing behaviour, so no test would ever catch it. `subtle` is
/// the small, widely audited crate built for exactly this, with the
/// optimisation barriers needed to stop the compiler undoing the work. A
/// security primitive whose failure mode is invisible is the case where
/// taking the dependency is clearly right.
///
/// The length check still short-circuits, which does leak the expected
/// token's length. That is standard practice (`ct_eq` requires equal-length
/// slices anyway) and a far smaller signal than a byte-by-byte early exit.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.ct_eq(b).into()
}

/// Strips the `Bearer ` scheme prefix from an `Authorization` header value.
///
/// RFC 7235 §2.1 makes the auth-scheme token case-insensitive, so a client
/// sending `bearer <token>` or `BEARER <token>` is conformant and must be
/// accepted. Only the scheme is case-insensitive; the credential itself is
/// returned untouched and still compared byte-for-byte in constant time.
fn strip_bearer_prefix(value: &str) -> Option<&str> {
    const SCHEME: &str = "bearer ";
    let (scheme, token) = value.split_at_checked(SCHEME.len())?;
    if scheme.eq_ignore_ascii_case(SCHEME) {
        Some(token)
    } else {
        None
    }
}

pub async fn require_bearer_token(expected_token: String, req: Request, next: Next) -> Response {
    if expected_token.is_empty() {
        tracing::warn!(target: "redwrench::audit", "rejected request: server has an empty expected bearer token configured");
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(axum::body::Body::empty())
            .unwrap();
    }

    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(strip_bearer_prefix);

    match provided {
        Some(token) if constant_time_eq(token, &expected_token) => next.run(req).await,
        _ => {
            tracing::warn!(target: "redwrench::audit", "rejected request with invalid or missing bearer token");
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::empty())
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_0_0_0_0_without_override() {
        let result = validate_bind_address("0.0.0.0:8443", false);
        assert!(result.is_err());
    }

    #[test]
    fn allows_0_0_0_0_with_explicit_override() {
        let result = validate_bind_address("0.0.0.0:8443", true);
        assert!(result.is_ok());
    }

    #[test]
    fn allows_a_specific_tailscale_style_address_without_override() {
        let result = validate_bind_address("100.64.0.1:8443", false);
        assert!(result.is_ok());
    }

    #[test]
    fn allows_localhost_without_override() {
        let result = validate_bind_address("127.0.0.1:8443", false);
        assert!(result.is_ok());
    }

    #[test]
    fn refuses_bracketed_ipv6_wildcard_without_override() {
        let result = validate_bind_address("[::]:8443", false);
        assert!(result.is_err());
    }

    #[test]
    fn allows_bracketed_ipv6_wildcard_with_explicit_override() {
        let result = validate_bind_address("[::]:8443", true);
        assert!(result.is_ok());
    }

    #[test]
    fn refuses_an_ipv4_mapped_wildcard_without_override() {
        // `::ffff:0.0.0.0` is a different bit pattern from `::`, so
        // `Ipv6Addr::is_unspecified()` returns false for it, but binding a
        // dual-stack socket here still listens on every IPv4 interface.
        let result = validate_bind_address("[::ffff:0.0.0.0]:8443", false);
        assert!(result.is_err());
    }

    #[test]
    fn allows_an_ipv4_mapped_wildcard_with_explicit_override() {
        let result = validate_bind_address("[::ffff:0.0.0.0]:8443", true);
        assert!(result.is_ok());
    }

    #[test]
    fn allows_an_ipv4_mapped_address_naming_a_real_interface() {
        // The unmap-and-retest must not over-broaden into rejecting every
        // mapped address: this one names one specific private interface.
        for addr in ["[::ffff:192.168.1.1]:8443", "[::ffff:127.0.0.1]:8443"] {
            assert!(
                validate_bind_address(addr, false).is_ok(),
                "{addr} should be allowed without the override flag"
            );
        }
    }

    #[test]
    fn allows_a_specific_ipv6_address_without_override() {
        let result = validate_bind_address("[::1]:8443", false);
        assert!(result.is_ok());
    }

    #[test]
    fn the_constant_time_comparison_still_behaves_like_equality() {
        assert!(constant_time_eq("s3cr3t", "s3cr3t"));
        assert!(!constant_time_eq("s3cr3t", "S3CR3T"));
        assert!(!constant_time_eq("s3cr3t", "s3cr3t "));
        assert!(!constant_time_eq("s3cr3t", ""));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn the_bearer_scheme_prefix_is_matched_case_insensitively() {
        // RFC 7235 §2.1: the auth-scheme token is case-insensitive.
        for header_value in [
            "Bearer s3cr3t",
            "bearer s3cr3t",
            "BEARER s3cr3t",
            "BeArEr s3cr3t",
        ] {
            assert_eq!(
                strip_bearer_prefix(header_value),
                Some("s3cr3t"),
                "failed for {header_value:?}"
            );
        }
    }

    #[test]
    fn the_credential_itself_stays_case_sensitive_and_other_schemes_are_rejected() {
        assert_eq!(strip_bearer_prefix("Bearer S3CR3T"), Some("S3CR3T"));
        assert_eq!(strip_bearer_prefix("Basic s3cr3t"), None);
        assert_eq!(strip_bearer_prefix("Bearers3cr3t"), None);
        assert_eq!(strip_bearer_prefix("Bearer"), None);
        assert_eq!(strip_bearer_prefix(""), None);
    }
}
