use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Request {
    domain: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Response {
    n: u128,
}

pub async fn root(Json(payload): Json<Request>) -> Json<Response> {
    tracing::info!("domain: {:?}", payload.domain);
    Json(Response { n: 0 })
}
