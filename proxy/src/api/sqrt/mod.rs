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

fn usqrt(n: u128, l: u128, r: u128, m: u128) -> u128 {
    if l == r - 1 {
        return m;
    } else if m * m > n {
        return usqrt(n, l, m, (l + m) / 2);
    } else {
        return usqrt(n, m, r, (m + r) / 2);
    }
}

pub async fn root(Json(payload): Json<Request>) -> Json<Response> {
    Json(Response {
        n: usqrt(payload.n, 0, payload.n, payload.n / 2),
    })
}
