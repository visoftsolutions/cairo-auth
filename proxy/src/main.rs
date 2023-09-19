mod api;
mod shutdown_signal;

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use axum::{
    routing::{get, post},
    Router,
};
use rustls::{ConnectionTrafficSecrets, OwnedTrustAnchor, RootCertStore};

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

pub async fn call() {
    let mut root_store = RootCertStore::empty();

    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        let subject = ta.subject.to_vec();
        let spki = ta.subject_public_key_info.to_vec();
        if let Some(ref nc) = ta.name_constraints {
            OwnedTrustAnchor::from_subject_spki_name_constraints(subject, spki, Some(nc.to_vec()))
        } else {
            OwnedTrustAnchor::from_subject_spki_name_constraints(subject, spki, None::<Vec<u8>>)
        }
    }));

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.enable_secret_extraction = true;

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();

    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    // stdout().write_all(&plaintext).unwrap();

    conn.peer_certificates()
        .iter()
        .for_each(|cert| println!("{:?}", cert));

    match conn.extract_secrets().unwrap().tx.1 {
        ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv } => {
            println!("AES128GCM key: {:?}, salt: {:?}, iv: {:?}", key, salt, iv);
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv } => {
            println!("AES256GCM key: {:?}, salt: {:?}, iv: {:?}", key, salt, iv);
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            println!("Chacha20Poly1305 key: {:?}, iv: {:?}", key, iv);
        }
        _ => {
            println!("Unknown ciphersuite");
        }
    }
}
