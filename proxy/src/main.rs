mod api;
mod shutdown_signal;

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use axum::{
    body::Body,
    http::Request,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use rustls::{ConnectionTrafficSecrets, OwnedTrustAnchor, RootCertStore};

use crate::{api::request, communication::call};

mod communication;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("ADDRESS").unwrap().parse().unwrap();

    let app = Router::new()
        .route("/", get(api::root))
        .route("/call", get(call))
        .route("/sqrt", post(api::sqrt::root))
        .route("/request", post(api::request::root));

    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(async {
            shutdown_signal::listen().await;
        })
        .await
        .unwrap();
}
