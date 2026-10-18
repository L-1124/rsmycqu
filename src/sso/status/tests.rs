use reqwest::StatusCode;
use rstest::rstest;

use reqwest::Url;

use super::redirect_summary;
use crate::{
    errors::{ApiError, session::SessionError, sso::SSOError},
    session::Session,
    sso::{
        check_sso_session,
        status::{SsoSessionStatus, is_cas_success_callback, validate_login_redirect},
        tests::{http_redirect, http_reply, run_test_tls_server},
    },
};

fn mock_login_page(flowkey: &str) -> String {
    format!(
        "<html><body>\
        <p id=\"login-croypto\">IGEOE4OMIBo=</p>\
        <p id=\"login-page-flowkey\">{flowkey}</p>\
        <p id=\"current-login-type\">UsernamePassword</p>\
        </body></html>"
    )
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_authenticated_two_step_chain() {
    let replies = vec![
        http_redirect("/authserver/login"),
        http_redirect("/landing"),
        http_reply("200 OK", "<html><body>Authenticated Landing</body></html>"),
        http_redirect("/authserver/login"),
    ];

    let session = Session::new();
    assert!(!session.is_login());
    let s = &session;

    let (res, reqs) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Ok(SsoSessionStatus::Authenticated)));
    assert!(!session.is_login());
    assert_eq!(reqs.len(), 4);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/login");
    assert_eq!(reqs[1].method, "GET");
    assert_eq!(reqs[1].path, "/authserver/login");
    assert_eq!(reqs[2].method, "GET");
    assert_eq!(reqs[2].path, "/landing");
    assert_eq!(reqs[3].method, "GET");
    assert_eq!(reqs[3].path, "/login");

    for req in &reqs {
        assert_ne!(req.method, "POST");
        assert!(!String::from_utf8_lossy(&req.body).contains("password"));
    }
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_authenticated_with_cas_confirmation() {
    let replies = vec![
        http_redirect("/landing"),
        http_reply("200 OK", "<html><body>Authenticated App</body></html>"),
        http_redirect("/landing"),
    ];

    let session = Session::new();
    let s = &session;

    let (res, reqs) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Ok(SsoSessionStatus::Authenticated)));
    assert_eq!(reqs.len(), 3);
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_unauthenticated_overrides_local_flag() {
    let replies = vec![http_reply("200 OK", &mock_login_page("flow-12345"))];

    let mut session = Session::new();
    session.is_login = true;
    let s = &session;

    let (res, reqs) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Ok(SsoSessionStatus::Unauthenticated)));
    assert!(session.is_login());
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/login");
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_rejects_active_pending_login() {
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&Session::new().export_snapshot().unwrap()).unwrap();
    let future_exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    snapshot["pending_login"] = serde_json::json!({
        "account": "active-user",
        "expires_at": future_exp,
        "stage": {"SecondFactor": {"info": {
            "phone": null, "phone_token": "token-1", "email": null, "execution": "exec-1"
        }}}
    });
    let session = Session::from_snapshot(&snapshot.to_string()).unwrap();
    let s = &session;

    let (res, reqs) = run_test_tls_server(vec![], |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(
        res,
        Err(ApiError::Inner {
            source: SSOError::InvalidPendingState { .. }
        })
    ));
    assert_eq!(reqs.len(), 0);
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_server_error_is_http_status() {
    let replies = vec![http_reply("500 Internal Server Error", "server crashed")];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(
        res,
        Err(ApiError::HttpStatus { status }) if status == StatusCode::INTERNAL_SERVER_ERROR
    ));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_waf_412_without_challenge_page_is_ruishu_error() {
    let replies = vec![http_reply("412 Precondition Failed", "ruishu block")];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(
        res,
        Err(ApiError::Session {
            source: SessionError::RuishuError { .. }
        })
    ));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_non_login_200_is_model_parse() {
    let replies = vec![http_reply(
        "200 OK",
        "<html><body>Under Maintenance</body></html>",
    )];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::ModelParse { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_missing_location_is_error() {
    let replies =
        vec!["HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::Website { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_cross_origin_redirect_is_rejected() {
    let replies = vec![http_redirect("https://evil.cqu.com/steal")];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::Website { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_third_cross_origin_redirect_is_rejected() {
    let replies = vec![
        http_redirect("/authserver/login"),
        http_redirect("https://evil.cqu.com/third-hop"),
    ];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::Website { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_embedded_credentials_redirect_is_rejected() {
    let replies = vec![http_redirect("https://user:pass@sso.cqu.edu.cn/landing")];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::Website { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_confirmation_failure_is_rejected() {
    let replies = vec![
        http_redirect("/landing"),
        http_reply("200 OK", "<html><body>App</body></html>"),
        http_reply("500 Internal Server Error", "cas down"),
    ];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert!(matches!(
        res,
        Err(ApiError::HttpStatus { status }) if status == StatusCode::INTERNAL_SERVER_ERROR
    ));
}

#[rstest]
#[case::self_redirect("/login")]
#[case::fragment_redirect("/login#ignored")]
#[tokio::test]
async fn test_check_sso_session_rejects_login_redirect_cycle(#[case] location: &str) {
    let (result, requests) =
        run_test_tls_server(vec![http_redirect(location)], |client| async move {
            check_sso_session(&client, &Session::new()).await
        })
        .await;
    assert!(matches!(result, Err(ApiError::Website { .. })));
    assert_eq!(requests.len(), 1);
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_rejects_multi_hop_redirect_cycle() {
    let replies = vec![
        http_redirect("/first"),
        http_redirect("/second"),
        http_redirect("/first#ignored"),
    ];
    let (result, requests) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, &Session::new()).await
    })
    .await;
    assert!(matches!(result, Err(ApiError::Website { .. })));
    assert_eq!(requests.len(), 3);
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_unresolved_redirect_is_not_authenticated() {
    let replies = vec![
        http_redirect("/first"),
        http_redirect("/second"),
        http_redirect("/third"),
    ];
    let (result, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, &Session::new()).await
    })
    .await;
    assert!(matches!(result, Err(ApiError::HttpStatus { status }) if status == StatusCode::FOUND));
}

#[rstest]
#[case::same_origin_path("https://sso.cqu.edu.cn/authserver/index.do", true)]
#[case::same_origin_with_query("https://sso.cqu.edu.cn/authserver/index.do?service=test", true)]
#[case::same_origin_explicit_port("https://sso.cqu.edu.cn:443/authserver/index.do", true)]
#[case::exact_cas_success_callback("https://self.cqu.edu.cn/cas-success", true)]
#[case::exact_cas_success_callback_explicit_port("https://self.cqu.edu.cn:443/cas-success", true)]
#[case::cas_callback_with_ticket("https://self.cqu.edu.cn/cas-success?ticket=ST-123456", true)]
#[case::cas_callback_with_opaque_ticket(
    "https://self.cqu.edu.cn/cas-success?ticket=custom_opaque_ticket_xyz",
    true
)]
#[case::cas_callback_with_encoded_amp_ticket(
    "https://self.cqu.edu.cn/cas-success?ticket=token%26param",
    true
)]
#[case::cas_callback_with_empty_ticket("https://self.cqu.edu.cn/cas-success?ticket=", false)]
#[case::cas_callback_with_empty_query("https://self.cqu.edu.cn/cas-success?", false)]
#[case::cas_callback_with_duplicate_ticket(
    "https://self.cqu.edu.cn/cas-success?ticket=ST-1&ticket=ST-2",
    false
)]
#[case::cas_callback_with_ticket_and_extra_query(
    "https://self.cqu.edu.cn/cas-success?ticket=ST-1&next=/evil",
    false
)]
#[case::cas_callback_with_ticket_and_fragment(
    "https://self.cqu.edu.cn/cas-success?ticket=ST-1#token",
    false
)]
#[case::cas_callback_with_ticket_and_trailing_amp(
    "https://self.cqu.edu.cn/cas-success?ticket=ST-1&",
    false
)]
#[case::cas_callback_with_ticket_user_pass(
    "https://user:pass@self.cqu.edu.cn/cas-success?ticket=ST-1",
    false
)]
#[case::cas_callback_with_ticket_alt_port(
    "https://self.cqu.edu.cn:8443/cas-success?ticket=ST-1",
    false
)]
#[case::cas_callback_with_ticket_http_downgrade(
    "http://self.cqu.edu.cn/cas-success?ticket=ST-1",
    false
)]
#[case::cas_callback_with_other_query("https://self.cqu.edu.cn/cas-success?next=/evil", false)]
#[case::cas_callback_with_fragment("https://self.cqu.edu.cn/cas-success#token", false)]
#[case::cas_callback_with_trailing_slash("https://self.cqu.edu.cn/cas-success/", false)]
#[case::cas_callback_other_path("https://self.cqu.edu.cn/login", false)]
#[case::cas_callback_root("https://self.cqu.edu.cn/", false)]
#[case::cas_callback_http_downgrade("http://self.cqu.edu.cn/cas-success", false)]
#[case::cas_callback_alt_port("https://self.cqu.edu.cn:8443/cas-success", false)]
#[case::cas_callback_with_user_pass("https://user:pass@self.cqu.edu.cn/cas-success", false)]
#[case::subdomain_spoof_prefix("https://evilsso.cqu.edu.cn/authserver/login", false)]
#[case::subdomain_spoof_suffix("https://sso.cqu.edu.cn.attacker.com/cas-success", false)]
#[case::other_cqu_subdomain("https://my.cqu.edu.cn/cas-success", false)]
#[case::other_cqu_subdomain_news("https://news.cqu.edu.cn/", false)]
#[case::external_domain("https://evil.cqu.com/cas-success", false)]
#[case::same_origin_http_downgrade("http://sso.cqu.edu.cn/authserver/index.do", false)]
#[case::same_origin_alt_port("https://sso.cqu.edu.cn:8443/authserver/index.do", false)]
#[case::same_origin_embedded_credentials(
    "https://user:pass@sso.cqu.edu.cn/authserver/index.do",
    false
)]
fn test_validate_login_redirect_boundaries(#[case] target_str: &str, #[case] should_accept: bool) {
    let base = Url::parse("https://sso.cqu.edu.cn/login").unwrap();
    let target = Url::parse(target_str).unwrap();
    let res = validate_login_redirect(&base, &target);
    assert_eq!(res.is_ok(), should_accept, "target={target_str}");
}

#[rstest]
#[case::exact_target("https://self.cqu.edu.cn/cas-success", true)]
#[case::explicit_port_target("https://self.cqu.edu.cn:443/cas-success", true)]
#[case::with_ticket("https://self.cqu.edu.cn/cas-success?ticket=ST-1", true)]
#[case::with_opaque_ticket(
    "https://self.cqu.edu.cn/cas-success?ticket=opaque_token_without_prefix",
    true
)]
#[case::with_encoded_amp_ticket("https://self.cqu.edu.cn/cas-success?ticket=token%26param", true)]
#[case::with_empty_ticket("https://self.cqu.edu.cn/cas-success?ticket=", false)]
#[case::with_empty_query("https://self.cqu.edu.cn/cas-success?", false)]
#[case::with_duplicate_ticket("https://self.cqu.edu.cn/cas-success?ticket=ST-1&ticket=ST-2", false)]
#[case::with_ticket_trailing_amp("https://self.cqu.edu.cn/cas-success?ticket=ST-1&", false)]
#[case::with_ticket_leading_amp("https://self.cqu.edu.cn/cas-success?&ticket=ST-1", false)]
#[case::with_ticket_and_fragment("https://self.cqu.edu.cn/cas-success?ticket=ST-1#token", false)]
#[case::subdomain_with_ticket("https://fake.self.cqu.edu.cn/cas-success?ticket=ST-1", false)]
#[case::scheme_http_with_ticket("http://self.cqu.edu.cn/cas-success?ticket=ST-1", false)]
#[case::alt_port_with_ticket("https://self.cqu.edu.cn:8443/cas-success?ticket=ST-1", false)]
#[case::user_pass_with_ticket("https://user:pass@self.cqu.edu.cn/cas-success?ticket=ST-1", false)]
#[case::with_other_query("https://self.cqu.edu.cn/cas-success?query=1", false)]
#[case::with_extra_query("https://self.cqu.edu.cn/cas-success?ticket=ST-1&next=/evil", false)]
#[case::with_fragment("https://self.cqu.edu.cn/cas-success#frag", false)]
#[case::wrong_path("https://self.cqu.edu.cn/cas-success-fake", false)]
#[case::subdomain("https://fake.self.cqu.edu.cn/cas-success", false)]
#[case::scheme_http("http://self.cqu.edu.cn/cas-success", false)]
fn test_is_cas_success_callback(#[case] target_str: &str, #[case] expected: bool) {
    let target = Url::parse(target_str).unwrap();
    assert_eq!(is_cas_success_callback(&target), expected);
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_exact_cas_success_callback_authenticated_with_confirmation() {
    let replies = vec![
        http_redirect("https://self.cqu.edu.cn/cas-success"),
        http_redirect("https://self.cqu.edu.cn/cas-success"),
    ];
    let session = Session::new();
    let s = &session;

    let (res, requests) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), SsoSessionStatus::Authenticated);
    assert_eq!(requests.len(), 2);
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_exact_cas_success_callback_unauthenticated_if_confirmation_returns_login_form()
 {
    let replies = vec![
        http_redirect("https://self.cqu.edu.cn/cas-success"),
        http_reply(
            "200 OK",
            &mock_login_page("flowkey-confirm-after-cas-success"),
        ),
    ];
    let session = Session::new();
    let s = &session;

    let (res, requests) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), SsoSessionStatus::Unauthenticated);
    assert_eq!(requests.len(), 2);
}

#[rstest]
#[case::standard_origin_no_query(
    "https://evil.cqu.com/secret/path/token-12345",
    "https://evil.cqu.com"
)]
#[case::standard_origin_single_query(
    "https://evil.cqu.com/sensitive/api?secret_token=abc",
    "https://evil.cqu.com?[query: 1]"
)]
#[case::standard_origin_multiple_query(
    "https://attacker.com/v1/auth?api_key=secret&user_pass=pass123&third=value",
    "https://attacker.com?[query: 3]"
)]
#[case::alt_port_no_query("https://evil.cqu.com:8443/secret/path", "https://evil.cqu.com:8443")]
#[case::alt_port_with_query(
    "https://evil.cqu.com:8443/steal?t=1&s=2",
    "https://evil.cqu.com:8443?[query: 2]"
)]
#[case::http_scheme_no_query("http://evil.cqu.com/path", "http://evil.cqu.com")]
#[case::http_alt_port(
    "http://evil.cqu.com:8080/path?key=val",
    "http://evil.cqu.com:8080?[query: 1]"
)]
#[case::credentials_redacted(
    "https://user:secret_pass@evil.cqu.com/leak_endpoint?token=abc",
    "https://evil.cqu.com?[query: 1]"
)]
fn test_redirect_summary_redaction(#[case] target_str: &str, #[case] expected_summary: &str) {
    let target = Url::parse(target_str).unwrap();
    let summary = redirect_summary(&target);
    assert_eq!(summary, expected_summary);
}

#[rstest]
fn test_validate_login_redirect_error_redacts_sensitive_path_and_query() {
    let base = Url::parse("https://sso.cqu.edu.cn/authserver/login").unwrap();
    let target = Url::parse(
        "https://attacker.com/oauth2/token/SUPER_SECRET_PATH_TOKEN_99999?SECRET_KEY=VAL_12345&ANOTHER_SECRET_KEY=VAL_67890",
    )
    .unwrap();

    let err = validate_login_redirect(&base, &target).unwrap_err();
    let msg = match err {
        ApiError::Website { msg } => msg,
        other => panic!("expected ApiError::Website, got: {other:?}"),
    };

    assert!(
        !msg.contains("SUPER_SECRET_PATH_TOKEN_99999"),
        "leaked secret path token in: {msg}"
    );
    assert!(!msg.contains("/oauth2/token/"), "leaked path in: {msg}");
    assert!(
        !msg.contains("SECRET_KEY"),
        "leaked secret query key in: {msg}"
    );
    assert!(
        !msg.contains("VAL_12345"),
        "leaked secret query value in: {msg}"
    );
    assert!(
        !msg.contains("ANOTHER_SECRET_KEY"),
        "leaked second secret query key in: {msg}"
    );
    assert!(
        !msg.contains("VAL_67890"),
        "leaked second secret query value in: {msg}"
    );

    assert_eq!(
        msg,
        "SSO redirect rejected: cross-origin redirect to https://attacker.com?[query: 2]"
    );
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_cross_origin_redirect_diagnostics_redacted() {
    let replies = vec![http_redirect(
        "https://evil.cqu.com/secret/path/victim_token?api_secret=leaked_val&client_secret=leaked_key",
    )];
    let session = Session::new();
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    match res {
        Err(ApiError::Website { msg }) => {
            assert!(
                !msg.contains("secret/path/victim_token"),
                "leaked path in: {msg}"
            );
            assert!(!msg.contains("api_secret"), "leaked query key in: {msg}");
            assert!(!msg.contains("leaked_val"), "leaked query value in: {msg}");
            assert!(!msg.contains("client_secret"), "leaked query key in: {msg}");
            assert!(!msg.contains("leaked_key"), "leaked query value in: {msg}");
            assert!(
                msg.contains("https://evil.cqu.com?[query: 2]"),
                "expected redacted origin and count, got: {msg}"
            );
        }
        other => panic!("expected ApiError::Website with redacted diagnostics, got: {other:?}"),
    }
}

#[rstest]
#[tokio::test]
async fn test_check_sso_session_cas_success_callback_with_ticket_authenticated() {
    let replies = vec![
        http_redirect("https://self.cqu.edu.cn/cas-success?ticket=ST-998877"),
        http_redirect("https://self.cqu.edu.cn/cas-success?ticket=ST-998877"),
    ];
    let session = Session::new();
    let s = &session;

    let (res, requests) = run_test_tls_server(replies, |client| async move {
        check_sso_session(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), SsoSessionStatus::Authenticated);
    assert_eq!(requests.len(), 2);
}
