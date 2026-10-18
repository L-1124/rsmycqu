use rstest::rstest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{
    errors::{ApiError, sso::SSOError},
    session::{Client, Session},
    sso::{
        LoginResult, SecondFactorInfo, SecondFactorKind, captcha_image, encrypt::encrypt_password,
        login, send_second_factor_code, submit_second_factor,
    },
    utils::{
        page_parser::SSOLoginPageData,
        test_fixture::{LoginData, login_data, shared_client},
    },
};

#[rstest]
fn test_login_page_encrypt() {
    let encrypted_password = encrypt_password("IGEOE4OMIBo=", "abc123456");
    assert_eq!(encrypted_password.unwrap(), "04fgkn+qsF1CZTXR/K/mbQ==");
}

#[rstest]
#[ignore = "真实网络测试，手动运行：cargo test --lib sso::tests::smoke_captcha_flow -- --ignored --nocapture"]
#[tokio::test]
async fn smoke_captcha_flow(shared_client: &'static Client) {
    let auth = std::env::var("RSMYCQU_AUTH").expect("set RSMYCQU_AUTH");
    let pwd = std::env::var("RSMYCQU_PWD").expect("set RSMYCQU_PWD");
    let mut session = Session::new();

    for i in 1..=6 {
        let r = login(
            shared_client,
            &mut session,
            &auth,
            "definitely_wrong_pwd",
            false,
            None,
        )
        .await;
        println!(
            "[{i}] wrong-pwd login -> {:?}",
            r.as_ref()
                .map(|v| format!("{v:?}"))
                .map_err(|e| e.to_string())
        );
    }

    let r = login(shared_client, &mut session, &auth, &pwd, false, None).await;
    println!("[3] login w/o captcha -> {:?}", r);

    if !matches!(r, Ok(LoginResult::CaptchaRequired)) {
        println!("[!] captcha not activated; verifying retry with real pwd");
        let r = login(shared_client, &mut session, &auth, &pwd, false, None).await;
        assert_eq!(r.unwrap(), LoginResult::Success);
        assert!(session.is_login());
        return;
    }

    let png = captcha_image(shared_client, &session).await.unwrap();
    println!("[4] captcha image: {} bytes, PNG magic OK", png.len());
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

    let path = std::env::temp_dir().join("rsmycqu_smoke_captcha.png");
    std::fs::write(&path, &png).unwrap();
    println!("[5] captcha saved: {}", path.display());

    println!("[6] open the PNG, read the code, then input here:");
    let mut code = String::new();
    std::io::stdin().read_line(&mut code).unwrap();
    let code = code.trim();

    let r = login(shared_client, &mut session, &auth, &pwd, false, Some(code)).await;
    println!(
        "[7] final login with captcha -> {:?}",
        r.as_ref()
            .map(|v| format!("{v:?}"))
            .map_err(|e| e.to_string())
    );
    assert_eq!(r.unwrap(), crate::sso::LoginResult::Success);
    assert!(session.is_login());
}

#[rstest]
#[ignore = "真实用户登录测试：RSMYCQU_AUTH=... RSMYCQU_PWD=... cargo test --lib sso::tests::test_real_user_login -- --ignored --nocapture"]
#[tokio::test]
async fn test_real_user_login(shared_client: &'static Client) {
    let auth = std::env::var("RSMYCQU_AUTH").expect("set RSMYCQU_AUTH");
    let pwd = std::env::var("RSMYCQU_PWD").expect("set RSMYCQU_PWD");
    let mut session = Session::new();
    let res = login(shared_client, &mut session, &auth, &pwd, false, None).await;
    println!("login res: {:?}", res);
    match res {
        Ok(LoginResult::SecondFactorRequired(info)) => {
            println!("成功进入二次身份验证！");
            println!("  手机已绑定: {}", info.phone_token.is_some());
            println!("  邮箱已绑定: {}", info.email.is_some());
        }
        Ok(other) => println!("登录返回: {:?}", other),
        Err(e) => println!("登录错误: {:?}", e),
    }
}

#[rstest]
#[ignore]
#[tokio::test]
async fn test_login(login_data: &LoginData, shared_client: &'static Client) {
    let mut session = Session::new();
    let res = login(
        shared_client,
        &mut session,
        &login_data.auth,
        &login_data.password,
        false,
        None,
    )
    .await;

    assert_eq!(res.unwrap(), LoginResult::Success);
}

fn serve_http(replies: Vec<String>) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let origin = url.clone();
    let server = std::thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0; 4096];
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
            }
            stream
                .write_all(reply.replace("$ORIGIN", &origin).as_bytes())
                .unwrap();
        }
    });
    (url, server)
}

fn http_reply(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn http_redirect(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

fn create_test_tls_acceptor() -> (TlsAcceptor, reqwest::tls::Certificate) {
    let subject_alt_names = vec!["sso.cqu.edu.cn".to_string(), "localhost".to_string()];
    let cert_key =
        rcgen::generate_simple_self_signed(subject_alt_names).expect("generate self-signed cert");

    let cert_der = cert_key.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    let server_config = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .expect("safe default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("valid server cert");

    let root_cert = reqwest::tls::Certificate::from_pem(cert_key.cert.pem().as_bytes())
        .expect("valid cert PEM for reqwest");

    (TlsAcceptor::from(Arc::new(server_config)), root_cert)
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn run_test_tls_server<F, Fut, T>(
    replies: Vec<String>,
    test_fn: F,
) -> (T, Vec<RecordedRequest>)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = T>,
{
    let (tls_acceptor, root_cert) = create_test_tls_acceptor();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("listener address");

    let recorded_requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let requests_clone = Arc::clone(&recorded_requests);

    let server_task = tokio::spawn(async move {
        for reply in replies {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let mut tls_stream = match tls_acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(_) => continue,
            };

            let mut buffer = [0u8; 1024];
            let mut raw = Vec::new();
            let header_end = loop {
                let count = match tls_stream.read(&mut buffer).await {
                    Ok(c) if c > 0 => c,
                    _ => break None,
                };
                raw.extend_from_slice(&buffer[..count]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(pos);
                }
            };

            let Some(pos) = header_end else {
                continue;
            };

            let header_text = String::from_utf8_lossy(&raw[..pos]);
            let mut lines = header_text.lines();
            let request_line = lines.next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let path = parts.next().unwrap_or("/").to_string();

            let mut headers = Vec::new();
            let mut content_length = 0usize;
            for line in lines {
                if let Some((name, val)) = line.split_once(':') {
                    let name = name.trim();
                    let val = val.trim();
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = val.parse().unwrap_or(0);
                    }
                    headers.push((name.to_string(), val.to_string()));
                }
            }

            let body_start = pos + 4;
            let mut body = raw[body_start..].to_vec();
            while body.len() < content_length {
                let count = match tls_stream.read(&mut buffer).await {
                    Ok(c) if c > 0 => c,
                    _ => break,
                };
                body.extend_from_slice(&buffer[..count]);
            }

            requests_clone.lock().await.push(RecordedRequest {
                method,
                path,
                headers,
                body,
            });

            let _ = tls_stream.write_all(reply.as_bytes()).await;
            let _ = tls_stream.flush().await;
            let _ = tls_stream.shutdown().await;
        }
    });

    let client = Client::custom(|builder| {
        builder
            .no_proxy()
            .add_root_certificate(root_cert)
            .resolve("sso.cqu.edu.cn", addr)
    })
    .expect("custom Client for TLS loopback tests");

    let output = test_fn(client).await;

    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server task did not complete within timeout")
        .expect("server task panicked");

    let requests = recorded_requests.lock().await.clone();
    (output, requests)
}

#[tokio::test]
async fn send_code_requires_explicit_business_success() {
    for (status, body, success) in [
        ("200 OK", r#"{"code":200,"data":{"result":true}}"#, true),
        ("200 OK", r#"{"code":200,"data":{"result":false}}"#, false),
        ("200 OK", r#"{"code":200}"#, false),
        ("200 OK", r#"{"code":401,"message":"Unauthorized"}"#, false),
        ("200 OK", "{}", false),
        ("200 OK", "<html>error</html>", false),
        ("200 OK", "", false),
        ("400 Bad Request", "", false),
    ] {
        let (url, server) = serve_http(vec![http_reply(status, body)]);
        let client = Client::custom(|builder| builder.no_proxy()).unwrap();
        let response = client.get(url).send().await.unwrap();
        let result = super::handle_send_code_response(response, "probe").await;
        server.join().unwrap();
        assert_eq!(result.is_ok(), success, "{status}: {body}");
    }
}

#[tokio::test]
async fn failed_landing_clears_login_state() {
    let redirect = "HTTP/1.1 302 Found\r\nLocation: $ORIGIN/landing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
    let (url, server) = serve_http(vec![redirect, http_reply("500 Internal Server Error", "")]);
    let client = Client::custom(|builder| builder.no_proxy()).unwrap();
    let mut session = Session::new();
    session.is_login = true;
    let response = client.get(url).send().await.unwrap();
    let result = super::handle_login_response(&client, &mut session, response).await;
    server.join().unwrap();
    assert!(matches!(
        result,
        Err(crate::errors::ApiError::Website { .. })
    ));
    assert!(!session.is_login());
}

#[test]
fn binding_responses_distinguish_absence_from_invalid_data() {
    use serde_json::json;
    assert_eq!(
        super::parse_binding(
            Some(json!({"tel":"phone-token","maskTel":"*******1230"})),
            SecondFactorKind::Sms
        )
        .unwrap()
        .as_deref(),
        Some("phone-token")
    );
    assert_eq!(
        super::parse_binding(Some(json!("user@example.com")), SecondFactorKind::Mail)
            .unwrap()
            .as_deref(),
        Some("user@example.com")
    );
    for kind in [SecondFactorKind::Sms, SecondFactorKind::Mail] {
        assert_eq!(super::parse_binding(None, kind).unwrap(), None);
        assert_eq!(super::parse_binding(Some(json!(null)), kind).unwrap(), None);
        assert!(super::parse_binding(Some(json!(42)), kind).is_err());
    }
    assert_eq!(
        super::parse_binding(Some(json!({"tel":""})), SecondFactorKind::Sms).unwrap(),
        None
    );
    assert_eq!(
        super::parse_binding(Some(json!("  ")), SecondFactorKind::Mail).unwrap(),
        None
    );
    assert!(
        super::parse_second_factor_response(r#"{"code":500,"message":"lookup failed"}"#, "lookup")
            .is_err()
    );
}

#[test]
fn bound_channels_are_explicit_and_never_fall_back() {
    use crate::errors::{ApiError, sso::SSOError};
    let mut info = SecondFactorInfo {
        phone: None,
        phone_token: None,
        email: None,
        execution: "execution".into(),
    };
    for kind in [SecondFactorKind::Sms, SecondFactorKind::Mail] {
        assert!(matches!(
            super::bound_contact(&info, kind),
            Err(ApiError::Inner {
                source: SSOError::NoSecondFactorBindings
            })
        ));
    }
    info.phone = Some("13800138000".into());
    info.email = Some("user@example.com".into());
    assert!(matches!(
        super::bound_contact(&info, SecondFactorKind::Sms),
        Err(ApiError::Inner {
            source: SSOError::PhoneNotBound
        })
    ));
    assert_eq!(
        super::bound_contact(&info, SecondFactorKind::Mail).unwrap(),
        "user@example.com"
    );
    info.phone_token = Some("phone-token".into());
    info.email = None;
    assert!(matches!(
        super::bound_contact(&info, SecondFactorKind::Mail),
        Err(ApiError::Inner {
            source: SSOError::EmailNotBound
        })
    ));
    assert_eq!(
        super::bound_contact(&info, SecondFactorKind::Sms).unwrap(),
        "phone-token"
    );
    info.email = Some("user@example.com".into());
    assert_eq!(
        super::bound_contact(&info, SecondFactorKind::Mail).unwrap(),
        "user@example.com"
    );
    assert_eq!(
        super::bound_contact(&info, SecondFactorKind::Sms).unwrap(),
        "phone-token"
    );
}

#[tokio::test]
async fn test_login_page_result_recognizes_marker_values_without_display_fields() {
    for marker in ["true", "smsLogin", "mailLogin"] {
        let session = Session::new();
        let s = &session;
        let replies = vec![
            http_reply("200 OK", r#"{"code":200,"data":{"tel":"token-123"}}"#),
            http_reply("200 OK", r#"{"code":200,"data":"user@example.com"}"#),
        ];
        let page = SSOLoginPageData {
            login_croypto: "crypto".into(),
            login_page_flowkey: format!("flowkey-{marker}"),
            captcha_url: String::new(),
            captcha_payload: String::new(),
            sso_second: marker.to_string(),
            phone_number: String::new(),
            user_email: String::new(),
            current_login_type: "UsernamePassword".into(),
            user_object_id: "user-123".into(),
        };
        let (result, requests) = run_test_tls_server(replies, |client| async move {
            super::login_page_result(&client, s, page).await
        })
        .await;

        let result = result.expect("login_page_result should succeed");
        match result {
            super::LoginResult::SecondFactorRequired(info) => {
                assert_eq!(info.phone, None);
                assert_eq!(info.phone_token.as_deref(), Some("token-123"));
                assert_eq!(info.email.as_deref(), Some("user@example.com"));
                assert_eq!(info.execution, format!("flowkey-{marker}"));
            }
            other => panic!("expected SecondFactorRequired, got {other:?}"),
        }
        assert_eq!(requests.len(), 2);
    }
}

#[tokio::test]
async fn test_login_page_result_preserves_false_and_non_second_page() {
    let session = Session::new();
    let s = &session;
    let page_false = SSOLoginPageData {
        login_croypto: "crypto".into(),
        login_page_flowkey: "flowkey-1".into(),
        captcha_url: String::new(),
        captcha_payload: String::new(),
        sso_second: "false".into(),
        phone_number: String::new(),
        user_email: String::new(),
        current_login_type: "UsernamePassword".into(),
        user_object_id: "user-123".into(),
    };
    let (res1, reqs1) = run_test_tls_server(vec![], |client| async move {
        super::login_page_result(&client, s, page_false).await
    })
    .await;
    assert_eq!(res1.unwrap(), super::LoginResult::IncorrectLoginCredentials);
    assert!(
        reqs1.is_empty(),
        "non-second page should not perform binding lookups"
    );

    let page_captcha = SSOLoginPageData {
        login_croypto: "crypto".into(),
        login_page_flowkey: "flowkey-2".into(),
        captcha_url: "https://sso.cqu.edu.cn/api/captcha/generate/DEFAULT".into(),
        captcha_payload: "payload".into(),
        sso_second: String::new(),
        phone_number: String::new(),
        user_email: String::new(),
        current_login_type: "UsernamePassword".into(),
        user_object_id: String::new(),
    };
    let (res2, reqs2) = run_test_tls_server(vec![], |client| async move {
        super::login_page_result(&client, s, page_captcha).await
    })
    .await;
    assert_eq!(res2.unwrap(), super::LoginResult::CaptchaRequired);
    assert!(reqs2.is_empty());
}

#[tokio::test]
async fn test_empty_binding_dispatcher_regression_returns_no_second_factor_bindings() {
    let session = Session::new();
    let s = &session;
    let replies = vec![
        http_reply("200 OK", r#"{"code":200,"data":null}"#),
        http_reply("200 OK", r#"{"code":200,"data":null}"#),
    ];
    let page = SSOLoginPageData {
        login_croypto: "crypto".into(),
        login_page_flowkey: "flowkey-empty-bindings".into(),
        captcha_url: String::new(),
        captcha_payload: String::new(),
        sso_second: "smsLogin".into(),
        phone_number: String::new(),
        user_email: String::new(),
        current_login_type: "UsernamePassword".into(),
        user_object_id: "user-test-obj-id".into(),
    };
    let (result, requests) = run_test_tls_server(replies, |client| async move {
        super::login_page_result(&client, s, page).await
    })
    .await;

    assert!(matches!(
        result,
        Err(ApiError::Inner {
            source: SSOError::NoSecondFactorBindings
        })
    ));
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].path,
        "/api/protected/sms/getPhoneNumberByUserId"
    );
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].path,
        "/api/protected/mail/publicNoToken/findMail"
    );
}
#[rstest]
#[case::both_unmasked(
    "13800138000",
    "student@cqu.edu.cn",
    Some("138****8000"),
    Some("13800138000"),
    Some("student@cqu.edu.cn"),
    0
)]
#[case::phone_masked_email_unmasked(
    "138****8000",
    "student@cqu.edu.cn",
    Some("138****8000"),
    Some("looked-up-phone-token"),
    Some("student@cqu.edu.cn"),
    1
)]
#[case::phone_unmasked_email_masked(
    "13800138000",
    "stu***@cqu.edu.cn",
    Some("138****8000"),
    Some("13800138000"),
    Some("looked-up-email@cqu.edu.cn"),
    1
)]
#[case::both_missing(
    "",
    "",
    None,
    Some("looked-up-phone-token"),
    Some("looked-up-email@cqu.edu.cn"),
    2
)]
#[tokio::test]
async fn test_login_page_result_prefers_unmasked_ssr_contacts_without_directory_id(
    #[case] ssr_phone: &str,
    #[case] ssr_email: &str,
    #[case] expected_phone_display: Option<&str>,
    #[case] expected_phone_token: Option<&str>,
    #[case] expected_email: Option<&str>,
    #[case] expected_lookups: usize,
) {
    let session = Session::new();
    let s = &session;
    let mut replies = Vec::new();
    if ssr_phone.is_empty() || ssr_phone.contains('*') {
        replies.push(http_reply(
            "200 OK",
            r#"{"code":200,"data":{"tel":"looked-up-phone-token"}}"#,
        ));
    }
    if ssr_email.is_empty() || ssr_email.contains('*') {
        replies.push(http_reply(
            "200 OK",
            r#"{"code":200,"data":"looked-up-email@cqu.edu.cn"}"#,
        ));
    }

    let user_obj_id = if expected_lookups > 0 {
        "user-mongo-id-123".to_string()
    } else {
        String::new()
    };

    let page = SSOLoginPageData {
        login_croypto: "crypto".into(),
        login_page_flowkey: "flowkey-ssr-test".into(),
        captcha_url: String::new(),
        captcha_payload: String::new(),
        sso_second: "smsLogin".into(),
        phone_number: ssr_phone.to_string(),
        user_email: ssr_email.to_string(),
        current_login_type: "smsLogin".into(),
        user_object_id: user_obj_id,
    };

    let (result, requests) = run_test_tls_server(replies, |client| async move {
        super::login_page_result(&client, s, page).await
    })
    .await;

    let outcome = result.expect("outcome should succeed");
    let super::LoginResult::SecondFactorRequired(info) = outcome else {
        panic!("expected SecondFactorRequired, got {outcome:?}");
    };

    assert_eq!(info.phone.as_deref(), expected_phone_display);
    assert_eq!(info.phone_token.as_deref(), expected_phone_token);
    assert_eq!(info.email.as_deref(), expected_email);
    assert_eq!(requests.len(), expected_lookups);

    // Secrecy invariants: neither Debug representation leaks unmasked raw contact
    let debug_str = format!("{info:?}");
    assert!(!debug_str.contains("13800138000"));
    if let Some(token) = expected_phone_token {
        assert!(!debug_str.contains(token));
    }
    assert!(!debug_str.contains("student@cqu.edu.cn"));
    assert!(!debug_str.contains("looked-up-email@cqu.edu.cn"));
}

#[rstest]
#[tokio::test]
async fn test_login_page_result_lookup_http_500_propagates_honest_error() {
    let session = Session::new();
    let s = &session;
    let replies = vec![http_reply("500 Internal Server Error", "server error")];
    let page = SSOLoginPageData {
        login_croypto: "crypto".into(),
        login_page_flowkey: "flowkey-error".into(),
        captcha_url: String::new(),
        captcha_payload: String::new(),
        sso_second: "smsLogin".into(),
        phone_number: String::new(),
        user_email: String::new(),
        current_login_type: "smsLogin".into(),
        user_object_id: "user-123".into(),
    };

    let (result, requests) = run_test_tls_server(replies, |client| async move {
        super::login_page_result(&client, s, page).await
    })
    .await;

    assert!(matches!(
        result,
        Err(ApiError::Inner {
            source: SSOError::SecondFactorError { .. }
        })
    ));
    assert_eq!(requests.len(), 1);
}

#[rstest]
#[tokio::test]
async fn test_login_page_result_masked_contact_missing_object_id_fails_explicitly() {
    let session = Session::new();
    let s = &session;
    let page = SSOLoginPageData {
        login_croypto: "crypto".into(),
        login_page_flowkey: "flowkey-no-id".into(),
        captcha_url: String::new(),
        captcha_payload: String::new(),
        sso_second: "smsLogin".into(),
        phone_number: "138****1234".into(),
        user_email: String::new(),
        current_login_type: "smsLogin".into(),
        user_object_id: String::new(),
    };

    let (result, requests) = run_test_tls_server(vec![], |client| async move {
        super::login_page_result(&client, s, page).await
    })
    .await;

    assert!(matches!(
        result,
        Err(ApiError::Inner {
            source: SSOError::SecondFactorError { .. }
        })
    ));
    assert!(requests.is_empty());
}

#[tokio::test]
async fn test_send_second_factor_code_sms_success_and_request_serialization() {
    let session = Session::new();
    let s = &session;
    let info = SecondFactorInfo {
        phone: Some("138****1234".into()),
        phone_token: Some("sample-phone-token-xyz".into()),
        email: None,
        execution: "execution-1".into(),
    };
    let info_ref = &info;
    let replies = vec![http_reply(
        "200 OK",
        r#"{"code":200,"data":{"result":true}}"#,
    )];
    let (result, requests) = run_test_tls_server(replies, |client| {
        let info = info_ref;
        async move { send_second_factor_code(&client, s, info, SecondFactorKind::Sms).await }
    })
    .await;

    assert!(
        result.is_ok(),
        "send_second_factor_code SMS should succeed: {result:?}"
    );
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/protected/sms/publicNoToken/sendSmsCode");
    assert!(
        req.header("content-type")
            .is_some_and(|c| c.contains("application/json"))
    );

    let payload: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(payload["phone"], "sample-phone-token-xyz");
    assert_eq!(payload["businessNo"], "0008");
}

#[tokio::test]
async fn test_send_second_factor_code_mail_success_and_request_serialization() {
    let session = Session::new();
    let s = &session;
    let info = SecondFactorInfo {
        phone: None,
        phone_token: None,
        email: Some("student@cqu.edu.cn".into()),
        execution: "execution-2".into(),
    };
    let info_ref = &info;
    let replies = vec![http_reply(
        "200 OK",
        r#"{"code":200,"data":{"result":true}}"#,
    )];
    let (result, requests) = run_test_tls_server(replies, |client| {
        let info = info_ref;
        async move { send_second_factor_code(&client, s, info, SecondFactorKind::Mail).await }
    })
    .await;

    assert!(
        result.is_ok(),
        "send_second_factor_code Mail should succeed: {result:?}"
    );
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.method, "POST");
    assert_eq!(
        req.path,
        "/api/protected/mail/publicNoToken/sendMailCode4SecondAuth"
    );
    assert!(
        req.header("content-type")
            .is_some_and(|c| c.contains("application/json"))
    );

    let payload: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(payload["type"], "DEFAULT");
    assert_eq!(payload["mbemail"], "student@cqu.edu.cn");
    assert_eq!(payload["businessNo"], "2025031701");
}

#[tokio::test]
async fn test_send_second_factor_code_unavailable_channel_preflight_no_fallback() {
    let session = Session::new();
    let s = &session;

    let mail_only = SecondFactorInfo {
        phone: None,
        phone_token: None,
        email: Some("user@cqu.edu.cn".into()),
        execution: "exec".into(),
    };
    let mail_only_ref = &mail_only;
    let (res_sms, reqs_sms) = run_test_tls_server(vec![], |client| {
        let mail_only = mail_only_ref;
        async move { send_second_factor_code(&client, s, mail_only, SecondFactorKind::Sms).await }
    })
    .await;
    assert!(matches!(
        res_sms,
        Err(ApiError::Inner {
            source: SSOError::PhoneNotBound
        })
    ));
    assert!(
        reqs_sms.is_empty(),
        "preflight should block network request"
    );

    let phone_only = SecondFactorInfo {
        phone: Some("138****0000".into()),
        phone_token: Some("token".into()),
        email: None,
        execution: "exec".into(),
    };
    let phone_only_ref = &phone_only;
    let (res_mail, reqs_mail) = run_test_tls_server(vec![], |client| {
        let phone_only = phone_only_ref;
        async move { send_second_factor_code(&client, s, phone_only, SecondFactorKind::Mail).await }
    })
    .await;
    assert!(matches!(
        res_mail,
        Err(ApiError::Inner {
            source: SSOError::EmailNotBound
        })
    ));
    assert!(
        reqs_mail.is_empty(),
        "preflight should block network request"
    );

    let neither = SecondFactorInfo {
        phone: None,
        phone_token: None,
        email: None,
        execution: "exec".into(),
    };
    let neither_ref = &neither;
    let (res_neither, reqs_neither) = run_test_tls_server(vec![], |client| {
        let neither = neither_ref;
        async move { send_second_factor_code(&client, s, neither, SecondFactorKind::Sms).await }
    })
    .await;
    assert!(matches!(
        res_neither,
        Err(ApiError::Inner {
            source: SSOError::NoSecondFactorBindings
        })
    ));
    assert!(reqs_neither.is_empty());
}

#[tokio::test]
async fn test_send_second_factor_code_error_responses() {
    let session = Session::new();
    let s = &session;
    let info = SecondFactorInfo {
        phone: None,
        phone_token: Some("token".into()),
        email: None,
        execution: "exec".into(),
    };
    let info_ref = &info;

    let replies1 = vec![http_reply(
        "200 OK",
        r#"{"code":200,"data":{"result":false}}"#,
    )];
    let (res1, _) = run_test_tls_server(replies1, |client| {
        let info = info_ref;
        async move { send_second_factor_code(&client, s, info, SecondFactorKind::Sms).await }
    })
    .await;
    assert!(matches!(
        res1,
        Err(ApiError::Inner {
            source: SSOError::SecondFactorError { .. }
        })
    ));

    let replies2 = vec![http_reply("200 OK", r#"{"code":500,"message":"发送频繁"}"#)];
    let (res2, _) = run_test_tls_server(replies2, |client| {
        let info = info_ref;
        async move { send_second_factor_code(&client, s, info, SecondFactorKind::Sms).await }
    })
    .await;
    assert!(matches!(
        res2,
        Err(ApiError::Inner {
            source: SSOError::SecondFactorError { .. }
        })
    ));

    let replies3 = vec![http_reply("412 Precondition Failed", "blocked")];
    let (res3, _) = run_test_tls_server(replies3, |client| {
        let info = info_ref;
        async move { send_second_factor_code(&client, s, info, SecondFactorKind::Sms).await }
    })
    .await;
    assert!(matches!(
        res3,
        Err(ApiError::Inner {
            source: SSOError::RuishuError { .. }
        })
    ));
}

#[tokio::test]
async fn test_submit_second_factor_successful_state_transition_and_serialization() {
    let mut session = Session::new();
    assert!(!session.is_login());

    let info = SecondFactorInfo {
        phone: Some("138****0000".into()),
        phone_token: Some("token".into()),
        email: None,
        execution: "flowkey-submit-test".into(),
    };
    let info_ref = &info;

    let replies = vec![
        http_redirect("/cas-landing"),
        http_reply("200 OK", "<html><body>Authenticated Landing</body></html>"),
        http_redirect("/cas-landing"),
    ];

    let s = &mut session;
    let (result, requests) = run_test_tls_server(replies, |client| {
        let info = info_ref;
        async move {
            submit_second_factor(
                &client,
                s,
                "20201234",
                info,
                SecondFactorKind::Sms,
                "654321",
            )
            .await
        }
    })
    .await;

    assert_eq!(result.unwrap(), LoginResult::Success);
    assert!(
        session.is_login(),
        "session should be marked logged in on success"
    );

    assert_eq!(requests.len(), 3);
    let post_req = &requests[0];
    assert_eq!(post_req.method, "POST");
    assert_eq!(post_req.path, "/login");

    let body_str = String::from_utf8_lossy(&post_req.body);
    let params: HashMap<_, _> = body_str
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();
    assert_eq!(params.get("username").copied(), Some("20201234"));
    assert_eq!(params.get("password").copied(), Some("654321"));
    assert_eq!(params.get("type").copied(), Some("smsLogin"));
    assert_eq!(params.get("_eventId").copied(), Some("submit"));
    assert_eq!(
        params.get("execution").copied(),
        Some("flowkey-submit-test")
    );
    assert_eq!(params.get("geolocation").copied(), Some(""));
    assert_eq!(params.get("captcha_code").copied(), Some(""));

    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].path, "/cas-landing");

    assert_eq!(requests[2].method, "GET");
    assert_eq!(requests[2].path, "/login");
}

#[tokio::test]
async fn test_submit_second_factor_unavailable_channel_preflight() {
    let mut session = Session::new();
    let info = SecondFactorInfo {
        phone: None,
        phone_token: None,
        email: Some("user@cqu.edu.cn".into()),
        execution: "flowkey-1".into(),
    };
    let info_ref = &info;

    let s = &mut session;
    let (result, requests) = run_test_tls_server(vec![], |client| {
        let info = info_ref;
        async move {
            submit_second_factor(
                &client,
                s,
                "20201234",
                info,
                SecondFactorKind::Sms,
                "123456",
            )
            .await
        }
    })
    .await;

    assert!(matches!(
        result,
        Err(ApiError::Inner {
            source: SSOError::PhoneNotBound
        })
    ));
    assert!(!session.is_login());
    assert!(
        requests.is_empty(),
        "preflight failure must not send any request"
    );
}

#[tokio::test]
async fn test_submit_second_factor_unsuccessful_state_transitions() {
    let info = SecondFactorInfo {
        phone: None,
        phone_token: Some("token".into()),
        email: None,
        execution: "flowkey-test".into(),
    };
    let info_ref = &info;

    let mut session1 = Session::new();
    let s1 = &mut session1;
    let replies1 = vec![http_reply("401 Unauthorized", "")];
    let (res1, _) = run_test_tls_server(replies1, |client| {
        let s = s1;
        let info = info_ref;
        async move {
            submit_second_factor(
                &client,
                s,
                "20201234",
                info,
                SecondFactorKind::Sms,
                "wrong_code",
            )
            .await
        }
    })
    .await;
    assert_eq!(res1.unwrap(), LoginResult::IncorrectLoginCredentials);
    assert!(!session1.is_login());

    let mut session2 = Session::new();
    let s2 = &mut session2;
    let replies2 = vec![
        http_redirect("/cas-landing"),
        http_reply("500 Internal Server Error", "error"),
    ];
    let (res2, _) = run_test_tls_server(replies2, |client| {
        let s = s2;
        let info = info_ref;
        async move {
            submit_second_factor(
                &client,
                s,
                "20201234",
                info,
                SecondFactorKind::Sms,
                "123456",
            )
            .await
        }
    })
    .await;
    assert!(matches!(res2, Err(ApiError::Website { .. })));
    assert!(!session2.is_login());
}
