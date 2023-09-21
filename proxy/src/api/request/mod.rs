use axum::Json;
use hyper::Method;
use serde::{Deserialize, Serialize};

use crate::communication::call;

#[derive(Debug, Deserialize)]
pub struct Request {
    domain: Vec<u8>,
}

impl Request {
    pub fn to_request(self) -> axum::http::Request<()> {
        let _body = ();
        let _path = "/";
        let domain = String::from_utf8(self.domain).expect("domain is not valid");
        // let url = ["https://", &domain, path].join("");
        let uri = "/";

        let mut req = axum::http::Request::new(());
        *req.method_mut() = Method::GET;
        *req.uri_mut() = uri.parse().expect("uri is not valid");

        let headers = req.headers_mut();
        headers.insert("Host", domain.parse().unwrap());
        headers.insert("Connection", "close".parse().unwrap());

        req
    }
}

#[derive(Debug, Serialize)]
pub struct Response {
    n: u128,
}

pub async fn root(Json(payload): Json<Request>) -> Json<Response> {
    tracing::info!("domain: {:?}", payload.domain);

    let proxy_req = payload.to_request();

    call(proxy_req).await;

    Json(Response { n: 0 })
}

#[test]
fn test_generate() {
    let req = Request {
        domain: "example.com".as_bytes().to_vec(),
    };
    let proxy_req = req.to_request();

    let (parts, _body) = proxy_req.into_parts();

    let mut result = format!("{} {} {:?}\r\n", parts.method, parts.uri, parts.version);
    for (key, value) in parts.headers.iter() {
        let header_value_str: &str = value.to_str().unwrap_or_default();
        result.push_str(&format!("{}: {}\r\n", key, header_value_str));
    }
    result.push_str("\r\n");

    let raw_req = concat!(
        "GET / HTTP/1.1\r\n",
        "host: example.com\r\n",
        "connection: close\r\n",
        "\r\n"
    );
    assert_eq!(result, raw_req);
}
