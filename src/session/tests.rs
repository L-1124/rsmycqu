//! [`Session`](super::Session) Cookies 注入测试

use super::{Session, reqwest};

const SSO_URL: &str = "https://sso.cqu.edu.cn/api/protected/auth/method/getActive";

#[test]
fn set_cookies_applies_to_matching_host() {
    let session = Session::new();
    session
        .set_cookies(
            "https://sso.cqu.edu.cn/login",
            "CtLgrmkSWHBZO=o-value; CtLgrmkSWHBZP=p-value",
        )
        .unwrap();

    let cookies = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(cookies.contains("CtLgrmkSWHBZO=o-value"));
    assert!(cookies.contains("CtLgrmkSWHBZP=p-value"));
}

#[test]
fn set_cookies_ignores_other_hosts() {
    let session = Session::new();
    session
        .set_cookies("https://sso.cqu.edu.cn/login", "CtLgrmkSWHBZO=o-value")
        .unwrap();

    let cookies = session.cookies("https://my.cqu.edu.cn/api/x").unwrap();
    assert!(cookies.is_none_or(|value| !value.contains("CtLgrmkSWHBZO")));
}

#[test]
fn set_cookies_tolerates_blank_segments() {
    let session = Session::new();
    session
        .set_cookies("https://sso.cqu.edu.cn/", " ; CtLgrmkSWHBZO=o-value ;  ")
        .unwrap();

    let cookies = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(cookies.contains("CtLgrmkSWHBZO=o-value"));
}

#[test]
fn cookies_is_none_without_injection() {
    let session = Session::new();
    assert!(session.cookies(SSO_URL).unwrap().is_none());
}

#[test]
fn set_ruishu_cookies_convenience() {
    let session = Session::new();
    session
        .set_ruishu_cookies("https://sso.cqu.edu.cn/login", "o-val", "p-val")
        .unwrap();

    let cookies = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(cookies.contains("CtLgrmkSWHBZO=o-val"));
    assert!(cookies.contains("CtLgrmkSWHBZP=p-val"));
}

#[test]
fn ruishu_block_only_for_cqu_hosts() {
    let url = |s: &str| reqwest::Url::parse(s).unwrap();
    let blocked = reqwest::StatusCode::PRECONDITION_FAILED;
    let ok = reqwest::StatusCode::OK;

    assert!(super::is_ruishu_blocked(
        &url("https://sso.cqu.edu.cn/api/x"),
        blocked
    ));
    assert!(super::is_ruishu_blocked(
        &url("https://cqu.edu.cn/"),
        blocked
    ));
    assert!(!super::is_ruishu_blocked(
        &url("https://evilcqu.edu.cn/"),
        blocked
    ));
    assert!(!super::is_ruishu_blocked(
        &url("https://sso.cqu.edu.cn/api/x"),
        ok
    ));
}

#[test]
fn test_session_set_basearr_from_cookie() {
    let session = Session::new();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_sessions.json")).unwrap();
    let cookie = fixture["session_1"]["cookie_t"].as_str().unwrap();

    session.set_basearr_from_cookie(cookie).unwrap();
    let ba = session.basearr().unwrap();
    assert_eq!(ba.len(), 160);
}

#[test]
fn test_extract_ts_cd() {
    let html_double = r#"<html><head><script>window.$_ts={};$_ts.cd="sample_cd_12345";$_ts.nsd=123;</script></head></html>"#;
    assert_eq!(super::extract_ts_cd(html_double), Some("sample_cd_12345"));

    let html_single =
        r#"<html><head><script>$_ts.cd='sample_cd_single_quote';</script></head></html>"#;
    assert_eq!(
        super::extract_ts_cd(html_single),
        Some("sample_cd_single_quote")
    );

    let html_none = "<html><body>regular page</body></html>";
    assert_eq!(super::extract_ts_cd(html_none), None);
}

#[test]
fn test_extract_ts_nsd() {
    let quoted = r#"<script>$_ts.nsd="107802";$_ts.cd="x";</script>"#;
    assert_eq!(super::extract_ts_nsd(quoted), Some(107802));

    let bare = r#"<script>window.$_ts={};$_ts.cd="x";$_ts.nsd=77374;</script>"#;
    assert_eq!(super::extract_ts_nsd(bare), Some(77374));

    let none = "<html><body>regular page</body></html>";
    assert_eq!(super::extract_ts_nsd(none), None);
}

#[tokio::test]
async fn execute_returns_invalid_request_error() {
    let client = reqwest::Client::new();
    let result = Session::new().execute(client.get("://invalid")).await;
    assert!(matches!(
        result,
        Err(crate::errors::session::SessionError::Build { .. })
    ));
}

#[tokio::test]
async fn execute_retries_once_with_updated_cookies_and_original_body() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0, "request ended before body");
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(bytes).unwrap());
            stream.write_all(
                b"HTTP/1.1 412 Precondition Failed\r\nSet-Cookie: CtLgrmkSWHBZO=server-o; Path=/\r\nContent-Length: 7\r\nConnection: close\r\n\r\nblocked"
            ).unwrap();
        }
        requests
    });

    let session = Session::new();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_sessions.json")).unwrap();
    session
        .set_basearr_from_cookie(fixture["session_1"]["cookie_t"].as_str().unwrap())
        .unwrap();
    let basearr = session.basearr().unwrap();
    let coder: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_coder.json")).unwrap();
    let vector = &coder["vectors"]["session_1"];
    assert!(session.set_ruishu_challenge_from_page(&format!(
        "$_ts.cd=\"{}\";$_ts.nsd={};",
        vector["cd"].as_str().unwrap(),
        vector["nsd"]
    )));
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("sso.cqu.edu.cn", address)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let response = session
        .execute(
            client
                .post(format!(
                    "http://sso.cqu.edu.cn:{}/api/protected/probe",
                    address.port()
                ))
                .form(&[("probe", "yes")]),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PRECONDITION_FAILED);
    assert_eq!(response.text().await.unwrap(), "blocked");
    let requests = server.join().unwrap();
    for request in &requests {
        assert!(request.starts_with("POST /api/protected/probe HTTP/1.1\r\n"));
        assert_eq!(request.split_once("\r\n\r\n").unwrap().1, "probe=yes");
    }
    assert!(requests[0].contains("CtLgrmkSWHBZP="));
    let cookie_header = requests[1]
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
        .unwrap();
    assert!(cookie_header.contains("CtLgrmkSWHBZO=server-o"));
    let cookie_t = cookie_header
        .split_once(':')
        .unwrap()
        .1
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("CtLgrmkSWHBZP="))
        .unwrap();
    let decrypted = super::ruishu::decrypt_cookie_t(cookie_t).unwrap();
    assert!(decrypted.crc_valid);
    assert_eq!(decrypted.basearr, basearr.as_ref());
}

/// 浏览器实测向量：站点对 `protected` 请求的 CSRF 校验值算法对照
#[test]
fn csrf_value_matches_browser_vector() {
    // Csrf-Key / Csrf-Value 取自真实浏览器请求
    let key = "q4JHUnlBQMcumQKiybl9kpTED3qXr1qT";
    assert_eq!(
        super::csrf_value(key),
        "c4e1292d0070e0a088fc2318a46c0e5c",
        "CSRF 值与站点 MD5 算法不一致"
    );
}

#[test]
fn csrf_headers_are_ascii_and_unique() {
    let (k1, v1) = super::csrf_headers();
    let (k2, _v2) = super::csrf_headers();
    let k1 = k1.to_str().unwrap();
    let v1 = v1.to_str().unwrap();

    assert_eq!(k1.len(), 32);
    assert!(k1.bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(v1.len(), 32);
    assert!(v1.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(k1, k2.to_str().unwrap());
    assert_eq!(super::csrf_value(k1), v1);
}

/// 真实网络：登录页挑战 + 站点脚本 → 受保护端点的 412 由会话全自动消化
///
/// RSMYCQU_MAINJS=<mainjs.js> cargo test --lib session::tests::ruishu_412_auto -- --ignored --nocapture
#[cfg(feature = "sso")]
#[ignore = "真实网络测试，需提供站点脚本"]
#[tokio::test]
async fn ruishu_412_auto_resolves_protected_endpoint() {
    let mainjs =
        std::fs::read_to_string(std::env::var("RSMYCQU_MAINJS").expect("set RSMYCQU_MAINJS"))
            .unwrap();
    const PROTECTED: &str = "https://sso.cqu.edu.cn/api/protected/auth/method/getActive";

    let client = crate::session::Client::default();
    let mut session = Session::new();
    session.set_mainjs(&mainjs);
    assert!(session.basearr().is_none());

    // 先把受保护端点打一次：无 basearr/挑战时不做处理，仅拿到 412
    let blocked = session.execute(client.get(PROTECTED)).await.unwrap();
    println!("首次请求状态 = {}", blocked.status());
    drop(blocked);

    // 登录页是瑞数挑战页，库内解析时会记住 cd/nsd（此处以 login 触发一次页面请求）
    let _ = crate::sso::login(
        &client,
        &mut session,
        "probe_auth",
        "probe_pwd",
        false,
        None,
    )
    .await;

    // 再次请求：412 → 用页面挑战纯算补 basearr 与 Cookie T → 重发
    let res = session
        .execute(client.get(PROTECTED))
        .await
        .expect("execute failed");
    println!("最终状态 = {}", res.status());
    println!("会话 basearr = {:?}", session.basearr().map(|b| b.len()));
    assert!(session.basearr().is_some(), "未自动补出 basearr");
    assert_eq!(res.status(), 200, "重发未通过防护层");
}

#[tokio::test]
async fn protected_requests_initialize_shared_cookie_t_without_retrying_400() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let len = stream.read(&mut buffer).unwrap();
                assert_ne!(len, 0);
                request.extend_from_slice(&buffer[..len]);
            }
            requests.push(String::from_utf8(request).unwrap());
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        }
        requests
    });
    let session = Session::new();
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_sessions.json")).unwrap();
    session
        .set_basearr_from_cookie(fixtures["session_1"]["cookie_t"].as_str().unwrap())
        .unwrap();
    let coder: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_coder.json")).unwrap();
    let vector = &coder["vectors"]["session_1"];
    session.set_ruishu_challenge_from_page(&format!(
        "$_ts.cd=\"{}\";$_ts.nsd={};",
        vector["cd"].as_str().unwrap(),
        vector["nsd"]
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("sso.cqu.edu.cn", address)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for path in ["/api/protected/sms/probe", "/api/protected/mail/probe"] {
        let res = session
            .execute(client.get(format!("http://sso.cqu.edu.cn:{}{path}", address.port())))
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    let requests = server.join().unwrap();
    let mut tokens = Vec::new();
    for request in &requests {
        let headers = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
            .unwrap();
        let token = headers
            .split_once(':')
            .unwrap()
            .1
            .split(';')
            .find_map(|part| part.trim().strip_prefix("CtLgrmkSWHBZP="))
            .unwrap();
        assert!(super::ruishu::decrypt_cookie_t(token).unwrap().crc_valid);
        tokens.push(token);
    }
    assert_eq!(
        tokens[0], tokens[1],
        "Cookie T must cover both protected endpoint paths"
    );
}

#[rstest::rstest]
#[case("second", 1)]
#[case("first", 2)]
fn changed_challenge_invalidates_inner_cipher(#[case] cd: &str, #[case] nsd: u32) {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
    session.set_basearr(&[0x5a; 160]).unwrap();
    let shared = session.clone();
    assert!(shared.set_ruishu_challenge_from_page(&format!("$_ts.cd=\"{cd}\";$_ts.nsd={nsd};")));
    assert_eq!(session.basearr(), None);
}

#[test]
fn unchanged_or_invalid_challenge_preserves_inner_cipher() {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
    session.set_basearr(&[0x5a; 160]).unwrap();
    assert_eq!(session.basearr().as_deref(), Some(&[0x5a; 160][..]));
    assert!(!session.set_ruishu_challenge_from_page("$_ts.cd=\"second\";"));
    assert_eq!(session.basearr().as_deref(), Some(&[0x5a; 160][..]));
}

#[test]
#[ignore = "requires RSMYCQU_MAINJS to verify regeneration across real challenge vectors"]
fn changed_challenge_regenerates_inner_cipher() {
    let mainjs =
        std::fs::read_to_string(std::env::var("RSMYCQU_MAINJS").expect("set RSMYCQU_MAINJS"))
            .expect("read RSMYCQU_MAINJS");
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_coder.json")).unwrap();
    let session = Session::new();
    session.set_mainjs(&mainjs);
    let url = reqwest::Url::parse(SSO_URL).unwrap();
    let mut previous = None;
    for name in ["session_1", "session_2"] {
        let vector = &fixture["vectors"][name];
        assert!(session.set_ruishu_challenge_from_page(&format!(
            "$_ts.cd=\"{}\";$_ts.nsd={};",
            vector["cd"].as_str().unwrap(),
            vector["nsd"]
        )));
        assert_eq!(session.basearr(), None);
        assert!(session.refresh_ruishu_cookie(&url).unwrap());
        let basearr = session.basearr().unwrap();
        assert_ne!(previous.as_deref(), Some(basearr.as_ref()));
        let cookie = session.cookies(SSO_URL).unwrap().unwrap();
        let token = cookie
            .split(';')
            .find_map(|part| part.trim().strip_prefix("CtLgrmkSWHBZP="))
            .unwrap();
        let decoded = super::ruishu::decrypt_cookie_t(token).unwrap();
        assert!(decoded.crc_valid);
        assert_eq!(decoded.basearr, basearr.as_ref());
        previous = Some(basearr);
    }
}

#[test]
fn changed_challenge_cannot_reuse_cipher_without_mainjs() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_coder.json")).unwrap();
    let session = Session::new();
    for name in ["session_1", "session_2"] {
        let vector = &fixture["vectors"][name];
        assert!(session.set_ruishu_challenge_from_page(&format!(
            "$_ts.cd=\"{}\";$_ts.nsd={};",
            vector["cd"].as_str().unwrap(),
            vector["nsd"]
        )));
        if name == "session_1" {
            session.set_basearr(&[0x5a; 160]).unwrap();
        }
    }
    let result = session.refresh_ruishu_cookie(&reqwest::Url::parse(SSO_URL).unwrap());
    assert!(matches!(
        result,
        Err(super::SessionError::RuishuError { .. })
    ));
}

#[rstest::rstest]
fn test_session_set_basearr_rejects_invalid_lengths() {
    let session = Session::new();
    assert!(session.set_basearr(&[]).is_err());
    assert!(session.set_basearr(&[0u8; 15]).is_err());
    assert!(session.set_basearr(&[0u8; 17]).is_err());
    assert!(session.set_basearr(&[0u8; 160]).is_ok());
    assert!(session.set_basearr(&[0u8; 288]).is_ok());
    assert!(session.set_basearr(&vec![0u8; 4096]).is_ok());
    assert!(
        session
            .set_basearr(&vec![0u8; super::ruishu::MAX_BASEARR_LEN + 1])
            .is_err()
    );
}
