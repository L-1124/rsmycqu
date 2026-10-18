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
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
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
#[case("second", 1)]
#[case("first", 2)]
fn changed_challenge_invalidates_obsolete_cookie_t(#[case] cd: &str, #[case] nsd: u32) {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
    session
        .set_ruishu_cookies(
            "https://sso.cqu.edu.cn/login",
            "server_cookie_o",
            "stale_client_cookie_t",
        )
        .unwrap();
    session
        .set_ruishu_cookies(
            "https://my.cqu.edu.cn/",
            "server_cookie_s",
            "stale_cookie_t",
        )
        .unwrap();
    session
        .set_cookies("https://example.com/api", "CtLgrmkSWHBZP=foreign_cookie")
        .unwrap();

    let before = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(before.contains("CtLgrmkSWHBZO=server_cookie_o"));
    assert!(before.contains("CtLgrmkSWHBZP=stale_client_cookie_t"));

    assert!(session.set_ruishu_challenge_from_page(&format!("$_ts.cd=\"{cd}\";$_ts.nsd={nsd};")));

    let after = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(
        after.contains("CtLgrmkSWHBZO=server_cookie_o"),
        "Cookie O must be preserved across challenge change"
    );
    assert!(
        !after.contains("CtLgrmkSWHBZP="),
        "Stale Cookie T must be purged upon explicit challenge change"
    );
    let mycqu = session.cookies("https://my.cqu.edu.cn/").unwrap().unwrap();
    assert!(mycqu.contains("CtLgrmkSWHBZS=server_cookie_s"));
    assert!(!mycqu.contains("CtLgrmkSWHBZT="));
    let foreign = session.cookies("https://example.com/api").unwrap().unwrap();
    assert!(
        foreign.contains("CtLgrmkSWHBZP=foreign_cookie"),
        "Foreign host cookies of the same name must never be purged"
    );
}

#[test]
fn unchanged_or_invalid_challenge_preserves_cookie_t() {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
    session
        .set_ruishu_cookies(
            "https://sso.cqu.edu.cn/login",
            "server_cookie_o",
            "client_cookie_t",
        )
        .unwrap();

    // 相同挑战
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
    let cookies = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(cookies.contains("CtLgrmkSWHBZP=client_cookie_t"));

    // 格式损坏的挑战
    assert!(!session.set_ruishu_challenge_from_page("$_ts.cd=\"second\";"));
    let cookies2 = session.cookies(SSO_URL).unwrap().unwrap();
    assert!(cookies2.contains("CtLgrmkSWHBZP=client_cookie_t"));
}

#[test]
fn snapshot_restore_respects_challenge_change_invalidation() {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"snap_cd\";$_ts.nsd=10;"));
    session
        .set_ruishu_cookies("https://sso.cqu.edu.cn/login", "snap_o", "snap_t")
        .unwrap();

    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();

    // 恢复后未变更挑战时保留快照中的 Cookie T
    let cookies = restored.cookies(SSO_URL).unwrap().unwrap();
    assert!(cookies.contains("CtLgrmkSWHBZO=snap_o"));
    assert!(cookies.contains("CtLgrmkSWHBZP=snap_t"));

    // 恢复后页面挑战变更，必须淘汰快照中过期的 Cookie T，保留 Cookie O
    assert!(restored.set_ruishu_challenge_from_page("$_ts.cd=\"rotated_cd\";$_ts.nsd=20;"));
    let after = restored.cookies(SSO_URL).unwrap().unwrap();
    assert!(after.contains("CtLgrmkSWHBZO=snap_o"));
    assert!(!after.contains("CtLgrmkSWHBZP="));

    // 导出并恢复处于"已作废/无Cookie T"状态的会话，恢复后快照同样保持无 T 状态
    let invalidated_snapshot = restored.export_snapshot().unwrap();
    let restored_invalidated = Session::from_snapshot(&invalidated_snapshot).unwrap();
    let re_cookies = restored_invalidated.cookies(SSO_URL).unwrap().unwrap();
    assert!(re_cookies.contains("CtLgrmkSWHBZO=snap_o"));
    assert!(!re_cookies.contains("CtLgrmkSWHBZP="));
}

#[tokio::test]
async fn execute_protected_refuses_to_send_stale_cookie_t_after_challenge_change() {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"first\";$_ts.nsd=1;"));
    session
        .set_ruishu_cookies(
            "https://sso.cqu.edu.cn/api/protected/test",
            "o_val",
            "stale_t",
        )
        .unwrap();

    // 挑战发生变更
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"second\";$_ts.nsd=2;"));

    // 在无 mainjs 情况下向受保护端点发请求：必须拒绝复用旧 T 发起请求，而应报错
    let client = reqwest::Client::new();
    let result = session
        .execute(client.get("https://sso.cqu.edu.cn/api/protected/probe"))
        .await;

    assert!(matches!(
        result,
        Err(super::SessionError::RuishuError { .. })
    ));
}

#[rstest::rstest]
fn test_snapshot_roundtrip_scope_and_attributes() {
    let session = Session::new();
    // 1. Host-only cookie: 无 Domain 属性，作用域限定于 host 本身
    session
        .set_cookies("https://sso.cqu.edu.cn/api/test", "host_only=val1")
        .unwrap();
    // 2. 泛域名 + Path + Secure + HttpOnly cookie
    session
        .cookie_jar
        .add_cookie_str(
            "dom_cookie=val2; Domain=cqu.edu.cn; Path=/api; Secure; HttpOnly",
            &reqwest::Url::parse("https://sso.cqu.edu.cn/api/test").unwrap(),
        )
        .unwrap();
    // 3. 限定深层路径 cookie
    session
        .cookie_jar
        .add_cookie_str(
            "path_cookie=val3; Path=/api/protected",
            &reqwest::Url::parse("https://sso.cqu.edu.cn/api/protected").unwrap(),
        )
        .unwrap();

    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();

    // 匹配 /api/protected 的 HTTPS 请求应当收到所有三条 cookie
    let cookies_all = restored
        .cookies("https://sso.cqu.edu.cn/api/protected")
        .unwrap()
        .unwrap();
    assert!(cookies_all.contains("host_only=val1"));
    assert!(cookies_all.contains("dom_cookie=val2"));
    assert!(cookies_all.contains("path_cookie=val3"));

    // 访问 /api/other 时不应携带 /api/protected 限定的 cookie
    let cookies_other = restored
        .cookies("https://sso.cqu.edu.cn/api/other")
        .unwrap()
        .unwrap();
    assert!(cookies_other.contains("host_only=val1"));
    assert!(cookies_other.contains("dom_cookie=val2"));
    assert!(!cookies_other.contains("path_cookie=val3"));

    // 跨子域名访问 my.cqu.edu.cn/api/test：Domain=cqu.edu.cn 应匹配，但 host_only 不应匹配
    let cookies_sub = restored
        .cookies("https://my.cqu.edu.cn/api/test")
        .unwrap()
        .unwrap();
    assert!(cookies_sub.contains("dom_cookie=val2"));
    assert!(!cookies_sub.contains("host_only=val1"));

    // 非安全明文 HTTP 请求不应匹配带有 Secure 属性的 cookie
    let cookies_http = restored.cookies("http://sso.cqu.edu.cn/api/test").unwrap();
    assert!(cookies_http.is_none_or(|c| !c.contains("dom_cookie=val2")));

    // 其它域名完全不匹配
    assert_eq!(
        restored.cookies("https://example.com/api/test").unwrap(),
        None
    );
}

#[rstest::rstest]
fn test_snapshot_drops_expired_cookies_and_preserves_session_cookies() {
    let session = Session::new();
    // 会话 Cookie（无 Expiration / Max-Age）
    session
        .cookie_jar
        .add_cookie_str(
            "sess_cookie=persistent_in_session; Path=/",
            &reqwest::Url::parse("https://sso.cqu.edu.cn/").unwrap(),
        )
        .unwrap();
    // 未来有效 Cookie
    session
        .cookie_jar
        .add_cookie_str(
            "future_cookie=future_val; Path=/; Max-Age=3600",
            &reqwest::Url::parse("https://sso.cqu.edu.cn/").unwrap(),
        )
        .unwrap();
    // 已过期 Cookie（Max-Age=0）
    session
        .cookie_jar
        .add_cookie_str(
            "expired_cookie=dead_val; Path=/; Max-Age=0",
            &reqwest::Url::parse("https://sso.cqu.edu.cn/").unwrap(),
        )
        .unwrap();

    let snapshot = session.export_snapshot().unwrap();
    // 导出的快照 JSON 不应包含已过期的 cookie 内容
    assert!(snapshot.contains("sess_cookie"));
    assert!(snapshot.contains("future_cookie"));
    assert!(!snapshot.contains("expired_cookie"));

    // 恢复会话，验证会话 cookie 与未来 cookie 依然有效
    let restored = Session::from_snapshot(&snapshot).unwrap();
    let cookies = restored
        .cookies("https://sso.cqu.edu.cn/")
        .unwrap()
        .unwrap();
    assert!(cookies.contains("sess_cookie=persistent_in_session"));
    assert!(cookies.contains("future_cookie=future_val"));
    assert!(!cookies.contains("expired_cookie"));

    // 即使有人篡改 JSON 注入包含过去 UTC 时间的 cookie，恢复时也必须被严格丢弃
    let tampered_json = snapshot.replace(
        "\"cookies\":[",
        r#""cookies":[{"raw_cookie":"tampered_expired=bad; Path=/","path":["/",true],"domain":{"HostOnly":"sso.cqu.edu.cn"},"expires":{"AtUtc":"2000-01-01T00:00:00Z"}},"#,
    );
    let restored_tampered = Session::from_snapshot(&tampered_json).unwrap();
    let cookies_tampered = restored_tampered
        .cookies("https://sso.cqu.edu.cn/")
        .unwrap()
        .unwrap();
    assert!(!cookies_tampered.contains("tampered_expired"));
}

#[rstest::rstest]
fn test_snapshot_rejects_corrupted_payloads_without_secret_leak() {
    // 1. 截断的 JSON
    let err = Session::from_snapshot("{\"version\":1,\"features\":[\"sso\"").unwrap_err();
    assert!(matches!(
        err,
        crate::errors::session::SessionError::SnapshotError { .. }
    ));
    let err_str = format!("{err}");
    assert!(!err_str.contains("sso")); // 不泄露载荷内容

    // 2. basearr hex 非法字符
    let mut corrupted: serde_json::Value =
        serde_json::from_str(&Session::new().export_snapshot().unwrap()).unwrap();
    corrupted["ruishu"]["basearr"] = "not_hex_chars_at_all_here_12345!".into();
    let err_hex = Session::from_snapshot(&corrupted.to_string()).unwrap_err();
    assert!(matches!(
        err_hex,
        crate::errors::session::SessionError::SnapshotError { .. }
    ));
    assert!(!format!("{err_hex}").contains("not_hex_chars"));

    // 3. basearr 长度非法（如 159 字节而非 160 字节）
    let bad_len_hex = "aa".repeat(159);
    corrupted["ruishu"]["basearr"] = bad_len_hex.clone().into();
    let err_len = Session::from_snapshot(&corrupted.to_string()).unwrap_err();
    assert!(matches!(
        err_len,
        crate::errors::session::SessionError::SnapshotError { .. }
    ));
    assert!(!format!("{err_len}").contains(&bad_len_hex)); // 绝不打印 hex 载荷明文
}

#[rstest::rstest]
fn test_snapshot_rejects_unsupported_version() {
    let snapshot = Session::new().export_snapshot().unwrap();
    let v2_snapshot = snapshot.replace("\"version\":1", "\"version\":2");
    let err = Session::from_snapshot(&v2_snapshot).unwrap_err();
    assert!(matches!(
        err,
        crate::errors::session::SessionError::UnsupportedVersion { version: 2 }
    ));

    let v0_snapshot = snapshot.replace("\"version\":1", "\"version\":0");
    let err0 = Session::from_snapshot(&v0_snapshot).unwrap_err();
    assert!(matches!(
        err0,
        crate::errors::session::SessionError::UnsupportedVersion { version: 0 }
    ));
}

#[rstest::rstest]
fn test_snapshot_rejects_feature_mismatch() {
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&Session::new().export_snapshot().unwrap()).unwrap();
    snapshot["features"] = serde_json::json!(["unsupported_future_service"]);
    let err = Session::from_snapshot(&snapshot.to_string()).unwrap_err();
    assert!(matches!(
        err,
        crate::errors::session::SessionError::FeatureMismatch { .. }
    ));
}

#[rstest::rstest]
fn test_snapshot_preserves_service_auth() {
    let session = Session::new();
    let mut infos = crate::session::access_info::AccessInfos::default();
    #[cfg(feature = "mycqu")]
    {
        infos.mycqu_access_info = Some(crate::session::access_info::MyCQUAccessInfo {
            auth_header: "Bearer test_oauth_token_secret".to_string(),
        });
    }
    let mut session = session.set_access_infos(infos);
    session.is_login = true;

    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();

    assert!(restored.is_login());
    #[cfg(feature = "mycqu")]
    {
        let mycqu_info = restored.access_infos().mycqu_access_info.as_ref().unwrap();
        assert_eq!(mycqu_info.auth_header, "Bearer test_oauth_token_secret");
    }
}

#[rstest::rstest]
fn test_snapshot_preserves_ruishu_atomic_pair() {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"atomic_cd\";$_ts.nsd=54321;"));
    let sample_basearr = [0x5cu8; 160];
    session.set_basearr(&sample_basearr).unwrap();

    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();

    assert_eq!(restored.basearr().as_deref(), Some(&sample_basearr[..]));
    assert_eq!(
        restored.ruishu_state.read().unwrap().challenge,
        Some(("atomic_cd".to_string(), 54321))
    );
}

#[rstest::rstest]
fn test_snapshot_ruishu_challenge_only_rebuilds_with_mainjs() {
    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"challenge_only\";$_ts.nsd=1111;"));
    assert_eq!(session.basearr(), None);

    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.basearr(), None);

    // 未设置 mainjs 时刷新应返回 RuishuError 要求 mainjs
    let url = reqwest::Url::parse(SSO_URL).unwrap();
    let res = restored.refresh_ruishu_cookie(&url);
    assert!(matches!(
        res,
        Err(crate::errors::session::SessionError::RuishuError { .. })
    ));
}

#[rstest::rstest]
fn test_snapshot_ruishu_injected_basearr_only() {
    let session = Session::new();
    let injected = [0x88u8; 160];
    session.set_basearr(&injected).unwrap();
    assert_eq!(session.basearr().as_deref(), Some(&injected[..]));

    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.basearr().as_deref(), Some(&injected[..]));
    assert!(restored.ruishu_state.read().unwrap().challenge.is_none());
}
#[rstest::rstest]
fn test_snapshot_supports_288_basearr() {
    let session = Session::new();
    let sample_288 = vec![0x42u8; 288];
    session.set_basearr(&sample_288).unwrap();
    let snapshot = session.export_snapshot().unwrap();
    let restored = Session::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.basearr().as_deref(), Some(sample_288.as_slice()));
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

#[rstest::rstest]
fn test_session_debug_redacts_secrets() {
    let session = Session::new();
    session
        .set_cookies(
            "https://sso.cqu.edu.cn/",
            "secret_cookie_name=secret_cookie_value",
        )
        .unwrap();
    let mut infos = crate::session::access_info::AccessInfos::default();
    #[cfg(feature = "mycqu")]
    {
        infos.mycqu_access_info = Some(crate::session::access_info::MyCQUAccessInfo {
            auth_header: "super_secret_token_12345".to_string(),
        });
    }
    let session = session.set_access_infos(infos);
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"secret_cd_hash\";$_ts.nsd=7777;"));
    session.set_basearr(&[0xee; 160]).unwrap();

    let debug_str = format!("{session:?}");
    // 绝不输出任何内部秘密
    assert!(!debug_str.contains("secret_cookie_name"));
    assert!(!debug_str.contains("secret_cookie_value"));
    assert!(!debug_str.contains("super_secret_token_12345"));
    assert!(!debug_str.contains("secret_cd_hash"));
    assert!(!debug_str.contains("eeeeeeee"));
}

#[test]
fn extract_mainjs_src_prefers_marked_script() {
    let html = r#"
        <script src="/vendor/app.js"></script>
        <script type="text/javascript" src="/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js" r='m'></script>
    "#;
    assert_eq!(
        super::extract_mainjs_src(html).as_deref(),
        Some("/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js")
    );
}

#[test]
fn extract_mainjs_src_requires_marked_script_no_fallback() {
    let html =
        r#"<script src='https://sso.cqu.edu.cn/a/b.js'></script><script src="/c.js"></script>"#;
    assert_eq!(super::extract_mainjs_src(html), None);
    assert_eq!(super::extract_mainjs_src("<html></html>"), None);
}

#[test]
fn page_challenge_records_mainjs_source() {
    let session = Session::new();
    let html = r#"<script src="/o1wscOsW7WGI/main.js" r='m'></script><script>$_ts.cd="cd-1";$_ts.nsd=42;</script>"#;
    assert!(session.set_ruishu_challenge_from_page(html));

    let recorded = session.mainjs_src();
    assert_eq!(
        recorded.as_ref().map(|u| u.as_str()),
        Some("https://sso.cqu.edu.cn/o1wscOsW7WGI/main.js")
    );
    assert!(session.ruishu_mainjs.read().expect("mainjs lock").is_none());
}

#[test]
fn test_validate_script_url_origin_boundaries() {
    let parse = |s: &str| reqwest::Url::parse(s).unwrap();

    assert!(
        super::validate_script_url(&parse(
            "https://sso.cqu.edu.cn/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js"
        ))
        .is_ok()
    );
    assert!(
        super::validate_script_url(&parse(
            "https://my.cqu.edu.cn/o1wscOsW7WGI/3LUNfBL1Sj60.19f0848.js"
        ))
        .is_ok()
    );
    assert!(
        super::validate_script_url(&parse("https://sso.cqu.edu.cn:443/static/main.js")).is_ok()
    );

    assert!(matches!(
        super::validate_script_url(&parse("http://sso.cqu.edu.cn/static/main.js")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://evil.cqu.edu.cn/main.js")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://card.cqu.edu.cn/main.js")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://example.com/main.js")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://sso.cqu.edu.cn:8443/main.js")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://admin:pass@sso.cqu.edu.cn/main.js")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://sso.cqu.edu.cn/main.js?token=secret")),
        Err(super::SessionError::RuishuError { .. })
    ));
    assert!(matches!(
        super::validate_script_url(&parse("https://sso.cqu.edu.cn/main.js#frag")),
        Err(super::SessionError::RuishuError { .. })
    ));
}

#[rstest::rstest]
#[case("/site.js", true)]
#[case("https://sso.cqu.edu.cn/site.js", true)]
#[case("//my.cqu.edu.cn/site.js", false)]
#[case("https://my.cqu.edu.cn/site.js", false)]
#[case("https://foreign.example/site.js", false)]
fn script_source_cannot_escape_challenge_origin(#[case] src: &str, #[case] accepted: bool) {
    let base = reqwest::Url::parse("https://sso.cqu.edu.cn/login").unwrap();
    assert_eq!(
        super::resolve_and_validate_script_url(&base, src).is_ok(),
        accepted
    );
}

#[test]
fn test_extract_mainjs_src_data_src_and_attributes() {
    let html_data_src = r#"<script data-src="/fake.js" r="m"></script>"#;
    assert_eq!(super::extract_mainjs_src(html_data_src), None);

    let html_data_r = r#"<script src="/other.js" data-r="m"></script>"#;
    assert_eq!(super::extract_mainjs_src(html_data_r), None);

    let html_inline_r = r#"<script r="m">window._$ts = {};</script>"#;
    assert_eq!(super::extract_mainjs_src(html_inline_r), None);

    let html_vendor = r#"<script src="/vendor/chunk.js"></script>"#;
    assert_eq!(super::extract_mainjs_src(html_vendor), None);

    let html_mixed = r#"
        <script src="/vendor/lib.js"></script>
        <script r="m">/* inline ruishu bootstrap */</script>
        <script type="text/javascript" src="/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js" r='m'></script>
    "#;
    assert_eq!(
        super::extract_mainjs_src(html_mixed).as_deref(),
        Some("/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js")
    );
}

#[test]
fn test_cache_invalidation_on_source_change() {
    let session = Session::new();
    let sso_html = r#"<script src="/o1wscOsW7WGI/sso.js" r='m'></script><script>$_ts.cd="cd_sso";$_ts.nsd=1111;</script>"#;
    assert!(session.set_ruishu_challenge_from_page(sso_html));
    session.set_mainjs("/* sso script */");
    session.set_basearr(&[0x11; 160]).unwrap();
    session
        .set_ruishu_cookies("https://sso.cqu.edu.cn/", "server_o", "client_t")
        .unwrap();

    assert!(session.basearr().is_some());
    assert!(session.ruishu_mainjs.read().unwrap().is_some());

    let my_url = reqwest::Url::parse("https://my.cqu.edu.cn/authserver/simple-user").unwrap();
    let my_script = super::resolve_and_validate_script_url(&my_url, "/o1wscOsW7WGI/my.js").unwrap();
    session
        .adopt_challenge_for_response(&my_url, "cd_my", 2222, Some(my_script))
        .unwrap();

    assert_eq!(session.basearr(), None);
    assert!(session.ruishu_mainjs.read().unwrap().is_none());

    let cookies = session.cookies("https://sso.cqu.edu.cn/").unwrap().unwrap();
    assert!(cookies.contains("CtLgrmkSWHBZO=server_o"));
    assert!(!cookies.contains("CtLgrmkSWHBZP="));
}

#[test]
fn test_initial_challenge_preserves_injected_basearr() {
    let session = Session::new();
    let sample = [0x77u8; 160];
    session.set_basearr(&sample).unwrap();

    let html = r#"<script>$_ts.cd="initial_cd";$_ts.nsd=3333;</script>"#;
    assert!(session.set_ruishu_challenge_from_page(html));
    assert_eq!(session.basearr().as_deref(), Some(&sample[..]));
}

#[rstest::rstest]
fn test_snapshot_rejects_unsafe_script_urls() {
    let base_snap = Session::new().export_snapshot().unwrap();

    let mut bad_host: serde_json::Value = serde_json::from_str(&base_snap).unwrap();
    bad_host["ruishu"]["mainjs_src"] = "https://evil.com/malicious.js".into();
    assert!(matches!(
        Session::from_snapshot(&bad_host.to_string()),
        Err(super::SessionError::SnapshotError { .. })
    ));

    let mut bad_scheme: serde_json::Value = serde_json::from_str(&base_snap).unwrap();
    bad_scheme["ruishu"]["mainjs_src"] = "http://sso.cqu.edu.cn/main.js".into();
    assert!(matches!(
        Session::from_snapshot(&bad_scheme.to_string()),
        Err(super::SessionError::SnapshotError { .. })
    ));

    let mut bad_cred: serde_json::Value = serde_json::from_str(&base_snap).unwrap();
    bad_cred["ruishu"]["mainjs_src"] = "https://attacker:pass@sso.cqu.edu.cn/main.js".into();
    assert!(matches!(
        Session::from_snapshot(&bad_cred.to_string()),
        Err(super::SessionError::SnapshotError { .. })
    ));

    let mut bad_query: serde_json::Value = serde_json::from_str(&base_snap).unwrap();
    bad_query["ruishu"]["mainjs_src"] = "https://sso.cqu.edu.cn/main.js?token=leak".into();
    assert!(matches!(
        Session::from_snapshot(&bad_query.to_string()),
        Err(super::SessionError::SnapshotError { .. })
    ));
}

#[rstest::rstest]
fn test_snapshot_resolves_legacy_relative_mainjs_src() {
    let base_snap = Session::new().export_snapshot().unwrap();
    let mut legacy: serde_json::Value = serde_json::from_str(&base_snap).unwrap();
    legacy["ruishu"]["mainjs_src"] = "/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js".into();
    legacy["ruishu"]["challenge"] = serde_json::json!({
        "cd": "legacy_cd",
        "nsd": 5555
    });

    let restored = Session::from_snapshot(&legacy.to_string()).unwrap();
    assert_eq!(
        restored.mainjs_src().as_ref().map(|u| u.as_str()),
        Some("https://sso.cqu.edu.cn/o1wscOsW7WGI/UUezYZrKq3dX.19f0848.js")
    );
}

#[rstest::rstest]
#[tokio::test]
async fn test_execute_only_one_412_retry() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_sessions.json")).unwrap();
    let initial_cookie_t = fixtures["session_1"]["cookie_t"].as_str().unwrap();

    let coder: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/ruishu_coder.json")).unwrap();
    let vector = &coder["vectors"]["session_1"];
    let cd = vector["cd"].as_str().unwrap().to_string();
    let nsd = vector["nsd"].as_u64().unwrap() as u32;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let server_cd = cd.clone();
    let server = std::thread::spawn(move || {
        let mut request_count = 0;
        let mut received_cookie_ts = Vec::new();
        while let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 2048];
            let len = stream.read(&mut buf).unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..len]);
            if let Some(cookie_line) = req_str
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
            {
                let ct = cookie_line
                    .split_once(':')
                    .unwrap()
                    .1
                    .split(';')
                    .find_map(|p| p.trim().strip_prefix("CtLgrmkSWHBZP="))
                    .map(|s| s.to_string());
                received_cookie_ts.push(ct);
            }
            request_count += 1;
            let response = format!(
                "HTTP/1.1 412 Precondition Failed\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<script>$_ts.cd=\"{server_cd}\";$_ts.nsd={nsd};</script>"
            );
            let _ = stream.write_all(response.as_bytes());
            if request_count >= 2 {
                break;
            }
        }
        (request_count, received_cookie_ts)
    });

    let session = Session::new();
    session.set_basearr_from_cookie(initial_cookie_t).unwrap();
    assert!(session.set_ruishu_challenge_from_page(&format!("$_ts.cd=\"{cd}\";$_ts.nsd={nsd};")));

    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("sso.cqu.edu.cn", address)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let res = session
        .execute(client.get(format!(
            "http://sso.cqu.edu.cn:{}/api/protected/test",
            address.port()
        )))
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::PRECONDITION_FAILED);
    let (count, cookie_ts) = server.join().unwrap();
    assert_eq!(count, 2, "must perform exactly one retry on 412");
    assert_eq!(cookie_ts.len(), 2);
    assert!(cookie_ts[0].is_some(), "first request had initial Cookie T");
    assert!(
        cookie_ts[1].is_some(),
        "second request had regenerated Cookie T"
    );
    assert_ne!(
        cookie_ts[0], cookie_ts[1],
        "retry must generate a new Cookie T"
    );
}

#[rstest::rstest]
#[tokio::test]
async fn test_execute_malformed_412_rejects_without_replay() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let server = std::thread::spawn(move || {
        let mut request_count = 0;
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            request_count += 1;
            let response = b"HTTP/1.1 412 Precondition Failed\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<script>$_ts.cd=\"corrupted_cd\";</script>";
            let _ = stream.write_all(response);
        }
        request_count
    });

    let session = Session::new();
    assert!(session.set_ruishu_challenge_from_page("$_ts.cd=\"old_cd\";$_ts.nsd=1234;"));

    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("sso.cqu.edu.cn", address)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let res = session
        .execute(client.get(format!("http://sso.cqu.edu.cn:{}/login", address.port())))
        .await;

    assert!(matches!(res, Err(super::SessionError::RuishuError { .. })));
    let count = server.join().unwrap();
    assert_eq!(
        count, 1,
        "must not retry when 412 carries a malformed challenge"
    );
}
