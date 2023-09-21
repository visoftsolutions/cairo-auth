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

fn status_code_from_bytes(bytes: Vec<u8>) -> Option<u16> {
    let res = String::from_utf8(bytes).ok()?;
    let headers = res.split("\r\n\r\n").next()?;
    let first_line = headers.split("\r\n").next()?;
    let status_code = first_line.split(" ").nth(1)?;
    status_code.parse::<u16>().ok()
}

pub type ConnectionResult = (Option<u16>, Vec<u8>, Vec<Vec<u8>>, Vec<u8>);

/// Sends a request to the proxy server and returns the response, together with certificates and connection secrets.
pub async fn call<T>(req: Request<T>) -> ConnectionResult {
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

    tls.write_all(request_bytes.as_bytes()).unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();

    // has to be after reading response, because handshake is lazy
    let certs = conn
        .peer_certificates()
        .into_iter()
        .map(|cert| format!("{:?}", cert.as_ref()).as_bytes().to_vec())
        .collect();

    let connection_secrets = match conn.extract_secrets().unwrap().tx.1 {
        ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv } => {
            format!("AES128GCM key: {:?}, salt: {:?}, iv: {:?}", key, salt, iv)
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv } => {
            format!("AES256GCM key: {:?}, salt: {:?}, iv: {:?}", key, salt, iv)
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            format!("Chacha20Poly1305 key: {:?}, iv: {:?}", key, iv)
        }
        _ => format!("Unknown cipher suite"),
    };

    let status_code = status_code_from_bytes(response.clone());

    (
        status_code,
        response,
        certs,
        connection_secrets.as_bytes().to_vec(),
    )
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

    let (status, proxy_response, certs, secrets) = call(req).await;

    assert_eq!(status, Some(200));
    assert!(proxy_response.len() > 0);
    assert!(certs.len() > 0);
    assert!(secrets.len() > 0);
}