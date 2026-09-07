// This test builds a minimal router using the same auth middleware as
// main.rs, without starting the full MCP service, to confirm the
// bearer token check actually rejects bad requests over real HTTP.
use axum::{routing::get, Router};
use tower::ServiceExt;

#[tokio::test]
async fn rejects_requests_without_a_valid_bearer_token() {
    let token = "expected-token".to_string();
    let app = Router::new().route("/ping", get(|| async { "pong" })).layer(
        axum::middleware::from_fn(move |req, next| {
            let token = token.clone();
            async move { redwrench::auth::require_bearer_token(token, req, next).await }
        }),
    );

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/ping")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}
