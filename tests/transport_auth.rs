// These tests build a minimal router using the same auth middleware as
// main.rs, without starting the full MCP service, to confirm the bearer
// token check behaves correctly over real HTTP.
//
// Both directions are covered deliberately. A rejection-only suite would
// still pass if the middleware regressed into rejecting everything, which
// would be a total outage rather than a security hole, so the positive case
// is what stops that regression reaching a release.
use axum::{routing::get, Router};
use tower::ServiceExt;

const EXPECTED_TOKEN: &str = "expected-token";

fn app() -> Router {
    let token = EXPECTED_TOKEN.to_string();
    Router::new()
        .route("/ping", get(|| async { "pong" }))
        .layer(axum::middleware::from_fn(move |req, next| {
            let token = token.clone();
            async move { redwrench::auth::require_bearer_token(token, req, next).await }
        }))
}

async fn status_for(authorization: Option<&str>) -> axum::http::StatusCode {
    let mut builder = axum::http::Request::builder().uri("/ping");
    if let Some(value) = authorization {
        builder = builder.header(axum::http::header::AUTHORIZATION, value);
    }
    app()
        .oneshot(builder.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn rejects_requests_without_a_valid_bearer_token() {
    assert_eq!(status_for(None).await, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn accepts_a_request_carrying_the_correct_bearer_token() {
    assert_eq!(
        status_for(Some("Bearer expected-token")).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn accepts_a_lowercase_bearer_scheme_per_rfc_7235() {
    assert_eq!(
        status_for(Some("bearer expected-token")).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_a_request_carrying_a_wrong_but_well_formed_token() {
    // Distinct from the missing-header case: the header is present and
    // correctly shaped, only the credential is wrong.
    assert_eq!(
        status_for(Some("Bearer wrong-token")).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
    // A same-length wrong token, so the constant-time compare's
    // length check is not what is doing the rejecting.
    assert_eq!(
        status_for(Some("Bearer expected-tokeN")).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rejects_a_non_bearer_authorization_scheme() {
    assert_eq!(
        status_for(Some("Basic expected-token")).await,
        axum::http::StatusCode::UNAUTHORIZED
    );
}
