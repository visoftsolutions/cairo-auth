mod api;
mod shutdown_signal;

use axum::{
    routing::{get, post},
    Router,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("ADDRESS").unwrap().parse().unwrap();

    let app = Router::new()
        .route("/", get(api::root))
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
