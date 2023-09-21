use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use axum::http::Request;
use rustls::{ClientConfig, ConnectionTrafficSecrets, OwnedTrustAnchor, RootCertStore};

fn serialize_request<T>(req: Request<T>) -> String {
    let (parts, _body) = req.into_parts();

    let mut result = format!("{} {} {:?}\r\n", parts.method, parts.uri, parts.version);
    for (key, value) in parts.headers.iter() {
        let header_value_str: &str = value.to_str().unwrap_or_default();
        result.push_str(&format!("{}: {}\r\n", key, header_value_str));
    }
    result.push_str("\r\n");
    result
}

pub fn rustls_config() -> ClientConfig {
    let mut root_store = RootCertStore::empty();

    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        let subject = ta.subject.to_vec();
        let spki = ta.subject_public_key_info.to_vec();
        let nc = ta.name_constraints.as_ref().map(|nc| nc.to_vec());
        OwnedTrustAnchor::from_subject_spki_name_constraints(subject, spki, nc)
    }));

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.enable_secret_extraction = true;

    config
}

pub async fn call<T>(req: Request<T>) {
    let config = Arc::new(rustls_config()); // TODO: move to global state

    let host_value = req
        .headers()
        .get("host")
        .expect("Host not present in request")
        .to_str()
        .expect("Host is not a valid header value");
    let server_name = host_value.try_into().expect("Host is not a valid DNS name");

    let mut conn = rustls::ClientConnection::new(config, server_name).unwrap();
    let mut sock = TcpStream::connect([host_value, "443"].join(":")).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let request_bytes = serialize_request(req);

    tls.write_all(
        request_bytes.as_bytes(),
        // concat!(
        //     "GET / HTTP/1.1\r\n",
        //     "host: example.com\r\n",
        //     "connection: close\r\n",
        //     "\r\n"
        // )
        // .as_bytes(),
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
    let domain = "example.com".to_owned();

    let mut req = axum::http::Request::new(());
    *req.method_mut() = hyper::Method::GET;
    *req.uri_mut() = "/".parse().unwrap();

    let headers = req.headers_mut();
    headers.insert("Host", domain.parse().unwrap());
    headers.insert("Connection", "close".parse().unwrap());

    call(req).await;
}
