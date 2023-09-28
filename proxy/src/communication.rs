use std::{
    io::{Read, Write},
    net::TcpStream,
    ops::{Add, Range},
    sync::Arc,
};

use axum::http::Request;

use p256::{
    ecdsa::{signature::Verifier, VerifyingKey},
    elliptic_curve::{
        generic_array::{ArrayLength, GenericArray},
        FieldBytes, FieldBytesSize, PrimeCurve,
    },
    pkcs8::der::pem::Base64Encoder,
    EncodedPoint, NistP256, PublicKey,
};
use p256::{
    ecdsa::{DerSignature, Signature},
    elliptic_curve::sec1::FromEncodedPoint,
};
use rustls::{ClientConfig, ConnectionTrafficSecrets, OwnedTrustAnchor, RootCertStore};
use sha256::digest;
use webpki::DnsNameRef;
use x509_parser::{
    der_parser::der::parse_der_sequence_defined_g,
    nom::Parser,
    prelude::{FromDer, TbsCertificateParser, X509Certificate},
    x509::AlgorithmIdentifier,
};

use generic_array::typenum::U9;

/// Maximum size of an ASN.1 DER encoded signature for the given elliptic curve.
pub type MaxSize<C> = <<FieldBytesSize<C> as Add>::Output as Add<U9>>::Output;

pub struct Sig {
    bytes: GenericArray<u8, MaxSize<NistP256>>,
    pub r_range: Range<usize>,
    pub s_range: Range<usize>,
}

impl Sig {
    pub fn r_and_s(&self) -> (&[u8], &[u8]) {
        (
            &self.bytes[self.r_range.clone()],
            &self.bytes[self.s_range.clone()],
        )
    }
}

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

    // has to be after reading response, because handshake doesn't block
    let certs = conn.peer_certificates().expect("no cert");

    ///// SIGNATURE PARSING BEGIN /////

    // load cert format of rutls
    let cert = certs.first().expect("no cert");
    let cert_ref = cert.0.as_ref();

    // parse to alternate format
    let web_cert = webpki::EndEntityCert::try_from(cert.0.as_ref()).expect("cert parsing failed");

    // verify dns name
    let dns_name = DnsNameRef::try_from_ascii_str("starkware.co").expect("dns name parsing failed");
    web_cert
        .verify_is_valid_for_dns_name(dns_name)
        .expect("cert validation failed");

    // parse cert data alone (without signature)
    let (not_cert_data, cert_data) = parse_der_sequence_defined_g(|i, _| {
        let mut tbs_parser = TbsCertificateParser::new().with_deep_parse_extensions(true);
        let (i, tbs_certificate) = tbs_parser.parse(i)?;

        Ok((i, cert))
    })(cert.0.as_ref())
    .expect("cert parsing failed");

    // extract signature data alone (without parsing) (didn't work)
    let (der_signature, algorithm) = parse_der_sequence_defined_g(|i, _| {
        // pass options to TbsCertificate parser
        let mut tbs_parser = TbsCertificateParser::new().with_deep_parse_extensions(true);
        let (i, _) = tbs_parser.parse(i)?;
        let (i, signature_algorithm) = AlgorithmIdentifier::from_der(i)?;

        Ok((i, signature_algorithm))
    })(cert.0.as_ref())
    .expect("cert parsing failed");

    let cert_data_bytes = &cert.0[..(cert.0.len() - not_cert_data.len())];
    assert_eq!(cert_data_bytes.len() + not_cert_data.len(), cert.0.len());

    let h = digest(cert_data_bytes);
    let h = h.as_bytes();
    println!("h: {:?}", h);

    // yet another cert type (didn't work)
    let (remainder, parsed) =
        X509Certificate::from_der(cert.0.as_ref()).expect("cert parsing failed");
    assert_eq!(remainder.len(), 0);
    let _issuer = parsed
        .issuer()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .expect("cn parsing failed")
        .to_owned();

    // public key of the issuer of certificate of starkware.co (used as and example domain), can be loaded together with domain name
    let cloudflare_pk_str = "04:B9:AD:4D:66:99:14:0B:46:EC:1F:81:D1:2A:50:1E:9D:03:15:2F:34:12:7D:2D:96:B8:88:38:9B:85:5F:8F:BF:BB:4D:EF:61:46:C4:C9:73:D4:24:4F:E0:EE:1C:CE:6C:B3:51:71:2F:6A:EE:4C:05:09:77:D3:72:62:A4:9B:D7";
    let cloudflare_pk_bytes = hex::decode(cloudflare_pk_str.replace(":", "")).unwrap();
    println!("cloudflare_pk_bytes: {:02X?}", cloudflare_pk_bytes);

    // printing in base64, to use online parsers
    let mut out = [0u8; 40960];
    let mut encoder = Base64Encoder::new(&mut out).unwrap();
    encoder.encode(cert_ref).unwrap();
    // thank god for https://lapo.it/asn1js/
    let encoded = encoder.finish().unwrap().to_owned();

    println!("cert: {}", encoded);

    let cloudflare_point = EncodedPoint::from_bytes(cloudflare_pk_bytes).unwrap();
    let cloudflare_pk = VerifyingKey::from_encoded_point(&cloudflare_point).unwrap();

    // actually loading the signature (didn't work)
    let signature = Signature::from_der(&der_signature).unwrap();

    // let signature = parsed.signature_value.data.as_ref();
    // let signature = Signature::from_bytes(signature);

    // binary identifier of elliptic curve algorithm
    let ecdsa_algorithm = hex::decode("06 08 2A 86 48 CE 3D 04 03 02".replace(" ", "")).unwrap();
    // manually finding second occurence of the algorithm identifier
    let algorithm_end = cert_ref
        .windows(ecdsa_algorithm.len())
        .position(|w| w == ecdsa_algorithm)
        .unwrap()
        + ecdsa_algorithm.len();
    let algorithm_end = cert_ref[algorithm_end..]
        .windows(ecdsa_algorithm.len())
        .position(|w| w == ecdsa_algorithm)
        .unwrap()
        + ecdsa_algorithm.len();
    println!("algorithm_end {}", algorithm_end);

    // printing just the signature in der format
    let mut out = [0u8; 40960];
    let mut encoder = Base64Encoder::new(&mut out).unwrap();
    encoder.encode(&cert_ref[algorithm_end..]).unwrap();
    let encoded: String = encoder.finish().unwrap().to_owned();
    println!("tail: {}", encoded);

    // let signature = DerSignature::from_bytes(der_signature).unwrap();
    // a way to extract private fields from parsed der signature (didn't work)
    // let signature: Sig = unsafe { std::mem::transmute(signature) };
    // let signature: Signature = signature.try_into().unwrap();

    // signature verification
    // cloudflare_pk
    //     .verify(h, &signature)
    //     .expect("cert signature verification failed");

    // extracting r and s, as they need to be send to cairo
    // let (r, s) = signature.r_and_s();
    // Signature::from_der().unwrap();

    // let parsed = X509Certificate::from_der(cert.0.as_ref())
    //     .expect("cert parsing failed")
    //     .1;

    // let cn = parsed
    //     .subject()
    //     .iter_common_name()
    //     .next()
    //     .unwrap()
    //     .as_str()
    //     .expect("cn parsing failed")
    //     .as_bytes();

    // let cn_pos = cert_bytes
    //     .windows(cn.len())
    //     .position(|w| w == cn)
    //     .expect("cn not found");
    // println!(
    //     "cn {} is at {} ({}{})",
    //     String::from_utf8(cn.to_vec()).unwrap(),
    //     cn_pos,
    //     cert_bytes[cn_pos],
    //     cert_bytes[cn_pos + 1]
    // );

    // alternate way of certificate verification using "parent" certificate
    // cert.verify_signature(None)
    //     .expect("cert signature verification failed");

    // println!("Cert pk: {:?}", cert.public_key());
    // println!(
    //     "Cert sj: {:?}",
    //     cert.subject().iter_common_name().next().unwrap().as_str()
    // );

    // verifying supported signature
    // let alg = match cert.signature_algorithm.algorithm.to_id_string().as_str() {
    //     "1.2.840.113549.1.1.11" => 1, // sha256WithRSAEncryption
    //     _ => 0,
    // };
    // println!("Cert alg: {:?}", alg);
    // println!("Cert sig: {:?}", cert.signature_value.data);

    // let h = digest(cert_bytes);
    ///// SIGNATURE PARSING END /////

    let certs = certs.iter().map(|cert| cert.0.clone()).collect();

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
