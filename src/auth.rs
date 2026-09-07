use std::net::SocketAddr;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

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
        .and_then(|v| v.strip_prefix("Bearer "));

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
}
