use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

pub fn validate_bind_address(addr: &str, allow_public: bool) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("'{addr}' is not a valid socket address (host:port): {e}"))?;
    if socket_addr.ip().is_unspecified() && !allow_public {
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

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
