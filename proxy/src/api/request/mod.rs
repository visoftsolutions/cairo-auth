use axum::Json;
use hyper::Method;
use serde::{Deserialize, Serialize};
use x509_parser::{
    nom::AsBytes,
    prelude::{FromDer, X509Certificate},
};

use crate::communication::call;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub domain: Vec<u8>,
}

impl Request {
    /// Converts the request data to a proxy request
    pub fn to_request(self) -> axum::http::Request<()> {
        let body = ();
        let domain = String::from_utf8(self.domain).expect("domain is not valid");
        let uri = "/";

        let mut req = axum::http::Request::new(body);
        *req.method_mut() = Method::GET;
        *req.uri_mut() = uri.parse().expect("uri is not valid");

        let headers = req.headers_mut();
        headers.insert("Host", domain.parse().unwrap());
        headers.insert("Connection", "close".parse().unwrap());

        req
    }
}

#[derive(Debug, Serialize, Default)]
struct CertData {
    data: Vec<u8>,
    domain_end: usize,
    signature_offset: usize,
    algorithm_offset: usize,
}

impl From<Vec<u8>> for CertData {
    fn from(cert: Vec<u8>) -> Self {
        let parsed = X509Certificate::from_der(cert.as_ref())
            .expect("cert parsing failed")
            .1;

        let find = |val: &[u8]| {
            cert[..]
                .windows(val.len())
                .position(|window| window == val)
                .expect("value present, but not found")
        };

        let algorithm = parsed.signature_algorithm.algorithm.as_bytes();
        let algorithm_offset = find(algorithm);

        let signature = parsed.signature_value.data.as_bytes();
        let signature_offset = find(signature);

        CertData {
            data: cert,
            domain_end: 0,
            algorithm_offset,
            signature_offset,
        }
    }
}

fn find_matching<'a>(whole: &'a [u8], small: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut skip = 0;

    loop {
        let next_dot = match small[skip..]
            .iter()
            .position(|&v| v.to_ascii_lowercase() == '.' as u8)
        {
            Some(pos) => pos + 1,
            None => break None,
        };

        let position_in_whole = whole
            .windows(small[skip..].len())
            .position(|w| w == &small[skip..]);

        if let Some(offset) = position_in_whole {
            let end: usize = offset + small[skip..].len();
            break Some((whole[offset..end].to_vec(), offset));
        } else {
            skip += next_dot;
        }
    }

    // let c = a
    //     .iter()
    //     .rev()
    //     .zip(b.iter().rev())
    //     .take_while(|(a, b)| a == b)
    //     .count();

    // println!("c: {}", c);

    // c
}

#[derive(Debug, Serialize)]
pub struct Response {
    status_code: u16,
    proxy_response: Vec<u8>,
    cert: CertData,
    connection_secrets: Vec<u8>,
}

pub async fn root(Json(payload): Json<Request>) -> Json<Response> {
    let domain = payload.domain.clone();
    tracing::info!(
        "domain: {}",
        String::from_utf8(domain).expect("domain is not valid")
    );
    let domain = payload.domain.clone();

    let proxy_req = payload.to_request();
    let (status_code, proxy_response, certs, secrets) = call(proxy_req).await;

    let certs: Vec<CertData> = certs.into_iter().map(Into::into).collect();
    let best = certs
        .into_iter()
        .map(|c| {
            let matching = find_matching(&c.data[..], &domain[..]).unwrap_or_default();
            (c, matching)
        })
        .fold((CertData::default(), (vec![], 0)), |c, v| {
            if v.1 .0.len() > c.1 .0.len() {
                v
            } else {
                c
            }
        });

    let (found_domain, found_offset) = best.1;
    let domain_end = if found_domain == &domain[..] {
        found_offset + found_domain.len()
    } else {
        unimplemented!("only exact domain matches supported")
    };

    let mut cert = best.0;
    cert.domain_end = domain_end;

    Json(Response {
        status_code: status_code.unwrap_or_default(),
        proxy_response,
        cert,
        connection_secrets: secrets,
    })
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

#[test]
fn test_find_matching() {
    let whole = "some.subdomain.at.example.com.and.the.rest".as_bytes();
    let small = "not.example.com".as_bytes();

    let result = find_matching(whole, small);
    assert_eq!(result, Some(("example.com".as_bytes().to_vec(), 18)));
}
