use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Request {
    n: u128,
}

#[derive(Debug, Serialize)]
pub struct Response {
    n: u128,
}

pub async fn root(Json(payload): Json<Request>) -> Json<Response> {
    Json(Response {
        n: payload.n * payload.n,
    })
}
