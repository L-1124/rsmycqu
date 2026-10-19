use std::{future::Future, sync::Arc, time::Duration};

use rstest::rstest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

use super::*;

const APP: &str = "https://lanunion-cqu-edu-cn.atrust.cqu.edu.cn/";

fn reply(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn api(data: Value) -> String {
    reply(
        "200 OK",
        "Content-Type: application/json\r\n",
        &json!({"code":0,"message":"OK","data":data}).to_string(),
    )
}

fn auth_config() -> String {
    api(json!({"security":{"csrfToken":"test-csrf"}}))
}

async fn serve<F, Fut, T>(replies: Vec<String>, run: F) -> (T, Vec<String>)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = T>,
{
    let cert = rcgen::generate_simple_self_signed(vec![
        "atrust.cqu.edu.cn".to_owned(),
        "sso.cqu.edu.cn".to_owned(),
        "lanunion-cqu-edu-cn.atrust.cqu.edu.cn".to_owned(),
    ])
    .unwrap();
    let root = reqwest::tls::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let config = ServerConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in replies {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        requests
    });
    let client = Client::custom(|builder| {
        builder
            .no_proxy()
            .add_root_certificate(root)
            .resolve("sso.cqu.edu.cn", address)
            .resolve("atrust.cqu.edu.cn", address)
            .resolve("lanunion-cqu-edu-cn.atrust.cqu.edu.cn", address)
            .timeout(Duration::from_secs(5))
    })
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), run(client))
        .await
        .unwrap();
    let requests = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    (result, requests)
}

fn cas_replies(auth_check: Value) -> Vec<String> {
    let mut shortcut = Url::parse("https://atrust.cqu.edu.cn/portal/shortcut.html").unwrap();
    shortcut.query_pairs_mut().append_pair(
        "data",
        &json!({"ticket":"env-ticket","env":{"need":true}}).to_string(),
    );
    vec![
        auth_config(),
        reply(
            "200 OK",
            "Content-Type: application/json\r\n",
            r#"{"code":75500002,"message":"not logged in","data":null}"#,
        ),
        reply(
            "302 Found",
            &format!("Location: {ATRUST_CAS_SERVICE}\r\n"),
            "",
        ),
        reply(
            "302 Found",
            &format!(
                "Location: {shortcut}\r\nSet-Cookie: sid=pending; Path=/; Secure; HttpOnly\r\n"
            ),
            "",
        ),
        reply("200 OK", "Content-Type: text/html\r\n", "shortcut"),
        auth_config(),
        api(Value::Null),
        reply(
            "200 OK",
            "Content-Type: application/json\r\nSet-Cookie: sid=online-sid; Path=/; Secure; HttpOnly\r\n",
            &json!({"code":0,"message":"OK","data":auth_check}).to_string(),
        ),
    ]
}

#[tokio::test]
async fn cas_handoff_scopes_cookies_and_keeps_business_auth_separate() {
    let mut replies = cas_replies(json!({"onlineInfo":{"isOnline":true},"nextService":""}));
    replies.extend([
        reply("200 OK", "Content-Type: text/html; charset=utf-8\r\n", r#"<script>var locationUrl = "https://atrust.cqu.edu.cn:443/controller/v1/public/verify?t=test"; location.replace(locationUrl);</script>"#),
        reply("302 Found", &format!("Location: {APP}?sdpAppCode=app-code&unitId=unit\r\n"), ""),
        reply("200 OK", "Content-Type: text/html\r\nSet-Cookie: sdp_user_token=app-token; Domain=atrust.cqu.edu.cn; Path=/; Secure; HttpOnly\r\n", "callback"),
        reply("401 Unauthorized", "Content-Type: application/json\r\n", r#"{"reason":"AUTH_MISSING"}"#),
    ]);
    let (session, requests) = serve(replies, |client| async move {
        let mut session = Session::new();
        session.is_login = true;
        access_atrust(&client, &mut session).await.unwrap();
        access_application(&client, &session, APP).await.unwrap();
        let business = session.execute(client.get(APP)).await.unwrap();
        assert_eq!(business.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(
            business.json::<Value>().await.unwrap()["reason"],
            "AUTH_MISSING"
        );
        session
    })
    .await;
    let report: Value =
        serde_json::from_str(requests[6].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(report["ticket"], "env-ticket");
    assert_eq!(report["deviceId"], report["env"]["endpoint"]["device_id"]);
    assert_eq!(report["env"]["endpoint"]["device"]["type"], "browser");
    assert!(
        requests[6]
            .to_ascii_lowercase()
            .contains("x-csrf-token: test-csrf")
    );
    assert!(!requests[8].contains("sid=online-sid"));
    assert!(requests[9].contains("sid=online-sid"));
    assert!(requests[11].contains("sdp_user_token=app-token"));
    let sibling = session
        .cookies("https://other.atrust.cqu.edu.cn/")
        .unwrap()
        .unwrap();
    assert!(sibling.contains("sdp_user_token=app-token"));
    assert!(!sibling.contains("sid=online-sid"));
    assert!(
        session
            .cookies("https://unrelated.example/")
            .unwrap()
            .is_none()
    );
}

#[rstest]
#[case(json!({"onlineInfo":{"isOnline":false},"nextService":""}))]
#[case(json!({"onlineInfo":{"isOnline":true},"nextService":"auth/clientCheck"}))]
#[tokio::test]
async fn incomplete_authentication_does_not_grant_permission(#[case] auth_check: Value) {
    serve(cas_replies(auth_check), |client| async move {
        let mut session = Session::new();
        session.is_login = true;
        assert!(matches!(
            access_atrust(&client, &mut session).await,
            Err(ApiError::Inner {
                source: ATrustError::Flow { .. }
            })
        ));
        assert!(session.access_infos.atrust_access_info.is_none());
    })
    .await;
}

#[tokio::test]
async fn restores_online_cookie_session_without_sso_login() {
    let (session, _) = serve(
        vec![auth_config(), api(json!({"isOnline":true}))],
        |client| async move {
            let mut session = Session::new();
            session.set_cookies(ATRUST_URL, "sid=existing").unwrap();
            access_atrust(&client, &mut session).await.unwrap();
            session
        },
    )
    .await;
    assert!(session.access_infos.atrust_access_info.is_some());
    assert!(!session.is_login);
}

#[tokio::test]
async fn server_failure_clears_previous_permission() {
    let failure = reply(
        "200 OK",
        "Content-Type: application/json\r\n",
        r#"{"code":123,"message":"denied","data":null}"#,
    );
    serve(vec![auth_config(), failure], |client| async move {
        let mut session = Session::new();
        session.access_infos.atrust_access_info = Some(ATrustAccessInfo {
            csrf_token: "stale".to_owned(),
        });
        assert!(matches!(
            access_atrust(&client, &mut session).await,
            Err(ApiError::Inner {
                source: ATrustError::Server { code: 123, .. }
            })
        ));
        assert!(session.access_infos.atrust_access_info.is_none());
    })
    .await;
}

#[rstest]
#[case("http://lanunion-cqu-edu-cn.atrust.cqu.edu.cn/")]
#[case("https://atrust.cqu.edu.cn/")]
#[case("https://app.atrust.cqu.edu.cn.evil.example/")]
#[case("https://user@app.atrust.cqu.edu.cn/")]
#[case("https://app.atrust.cqu.edu.cn:8443/")]
fn rejects_untrusted_proxy_origins(#[case] url: &str) {
    assert!(!is_application(&Url::parse(url).unwrap()));
}

#[tokio::test]
async fn application_permission_check_precedes_url_parsing_and_requests() {
    assert!(matches!(
        access_application(&Client::default(), &Session::new(), "invalid").await,
        Err(ApiError::NotAccess)
    ));
}

#[tokio::test]
async fn rejects_cross_origin_script_before_requesting_it() {
    let response = reply(
        "200 OK",
        "Content-Type: text/html\r\n",
        r#"<script>var locationUrl = "https://evil.example/"; location.replace(locationUrl);</script>"#,
    );
    serve(vec![response], |client| async move {
        let mut session = Session::new();
        session.access_infos.atrust_access_info = Some(ATrustAccessInfo {
            csrf_token: "test".to_owned(),
        });
        assert!(matches!(
            access_application(&client, &session, APP).await,
            Err(ApiError::Inner {
                source: ATrustError::Flow { .. }
            })
        ));
    })
    .await;
}

#[tokio::test]
async fn expired_gateway_auth_is_not_hidden_by_an_old_application_cookie() {
    let gateway_redirect = reply(
        "200 OK",
        "Content-Type: text/html\r\n",
        r#"<script>var locationUrl = "https://atrust.cqu.edu.cn/controller/v1/public/verify?t=test"; location.replace(locationUrl);</script>"#,
    );
    let rejected = reply("401 Unauthorized", "", "");
    serve(vec![gateway_redirect, rejected], |client| async move {
        let mut session = Session::new();
        session.access_infos.atrust_access_info = Some(ATrustAccessInfo {
            csrf_token: "test".to_owned(),
        });
        session.set_cookies(APP, "sdp_user_token=stale").unwrap();
        match access_application(&client, &session, APP).await {
            Err(ApiError::Request { source }) => {
                assert_eq!(source.status(), Some(reqwest::StatusCode::UNAUTHORIZED));
            }
            result => panic!("Expected gateway HTTP failure, got {result:?}"),
        }
    })
    .await;
}
