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

use crate::api::request;

pub async fn call(mut req: Request<Body>) {
    println!("call req: {:?}", req);
    println!("call method: {:?}", req.method());
    println!("call uri: {:?}", req.uri());
    println!("call headers: {:?}", req.headers());
    println!("call extensions: {:?}", req.extensions());

    req.headers().iter().for_each(|(k, v)| {
        println!("call header: {:?}={:?}", k, v);
    });

    println!("++++++++++++++++++++++++++");
    let mut root_store = RootCertStore::empty();

    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        let subject = ta.subject.to_vec();
        let spki = ta.subject_public_key_info.to_vec();
        let nc = ta.name_constraints.as_ref().map(|nc| nc.to_vec());
        OwnedTrustAnchor::from_subject_spki_name_constraints(subject, spki, nc)
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
            "host: example.com\r\n",
            "connection: close\r\n",
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

#[tokio::test]
async fn test() {
    call(Request::default()).await;
}
