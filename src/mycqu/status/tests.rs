use reqwest::StatusCode;
use rstest::rstest;

use crate::{
    errors::ApiError,
    mycqu::{check_mycqu_authorization, status::ServiceAuthorizationStatus},
    session::{Client, Session, access_info::MyCQUAccessInfo},
    sso::tests::{http_reply, run_test_tls_server},
};

fn session_with_mycqu_token(token: &str) -> Session {
    let mut session = Session::new();
    session.access_infos.mycqu_access_info = Some(MyCQUAccessInfo {
        auth_header: token.to_string(),
    });
    session
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_missing() {
    let session = Session::new();
    assert!(session.access_infos.mycqu_access_info.is_none());
    let s = &session;

    let (res, reqs) = run_test_tls_server(vec![], |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Missing);
    assert_eq!(reqs.len(), 0);
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_authorized() {
    let replies = vec![http_reply(
        "200 OK",
        r#"{"name":"测试学生","id":"20201234","code":"20201234","type":"student"}"#,
    )];
    let session = session_with_mycqu_token("valid-bearer-token");
    let s = &session;

    let (res, reqs) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/authserver/simple-user");
    assert_eq!(
        reqs[0].header("Authorization"),
        Some("Bearer valid-bearer-token")
    );
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_unauthorized_401() {
    let replies = vec![http_reply("401 Unauthorized", "expired token")];
    let session = session_with_mycqu_token("expired-token");
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Unauthorized);
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_unauthorized_403() {
    let replies = vec![http_reply("403 Forbidden", "forbidden")];
    let session = session_with_mycqu_token("forbidden-token");
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Unauthorized);
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_server_error_500_is_http_status() {
    let replies = vec![http_reply("500 Internal Server Error", "server crash")];
    let session = session_with_mycqu_token("some-token");
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert!(matches!(
        res,
        Err(ApiError::HttpStatus { status }) if status == StatusCode::INTERNAL_SERVER_ERROR
    ));
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_malformed_json_is_model_parse() {
    let replies = vec![http_reply(
        "200 OK",
        "<html><body>Gateway Error</body></html>",
    )];
    let session = session_with_mycqu_token("some-token");
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::ModelParse { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_empty_identity_fields_is_model_parse() {
    let replies = vec![http_reply(
        "200 OK",
        r#"{"name":"","id":"","code":"","type":""}"#,
    )];
    let session = session_with_mycqu_token("some-token");
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::ModelParse { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_independent_of_is_login() {
    let replies = vec![http_reply(
        "200 OK",
        r#"{"name":"张三","id":"20201234","code":"20201234","type":"student"}"#,
    )];
    let mut session = session_with_mycqu_token("restored-token");
    session.is_login = false;
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
    assert!(!session.is_login());
}

#[rstest]
#[tokio::test]
async fn test_check_mycqu_connection_failure_distinct_from_unauthorized() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client = Client::custom(|b| b.resolve("my.cqu.edu.cn", addr)).unwrap();
    let session = session_with_mycqu_token("token");

    let res = check_mycqu_authorization(&client, &session).await;

    match res {
        Err(err) => {
            assert!(!err.is_auth_error());
            assert!(
                err.is_network()
                    || matches!(err, ApiError::Request { .. } | ApiError::Session { .. })
            );
        }
        Ok(_) => panic!("expected connection failure, got success"),
    }
}

#[rstest]
#[tokio::test]
async fn test_restored_independent_service_grants() {
    let replies = vec![http_reply(
        "200 OK",
        r#"{"name":"李四","id":"20210001","code":"20210001","type":"student"}"#,
    )];
    let mut initial = Session::new();
    initial.access_infos.mycqu_access_info = Some(MyCQUAccessInfo {
        auth_header: "mycqu-only-token".to_string(),
    });
    let snapshot = initial.export_snapshot().unwrap();
    let session = Session::from_snapshot(&snapshot).unwrap();
    assert!(!session.is_login());
    #[cfg(feature = "card")]
    assert!(session.access_infos.card_access_info.is_none());
    let s = &session;

    let (res, _) = run_test_tls_server(replies, |client| async move {
        check_mycqu_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
}
