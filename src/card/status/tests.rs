use reqwest::StatusCode;
use rstest::rstest;

use crate::{
    card::{check_card_authorization, status::ServiceAuthorizationStatus},
    errors::ApiError,
    session::{Client, Session, access_info::CardAccessInfo},
    sso::tests::{http_reply, run_test_http_server},
};

fn session_with_card_grant() -> Session {
    let mut session = Session::new();
    session.access_infos.card_access_info = Some(CardAccessInfo {
        synjones_auth: None,
    });
    session
}

#[rstest]
#[tokio::test]
async fn test_check_card_missing() {
    let session = Session::new();
    assert!(session.access_infos.card_access_info.is_none());
    let s = &session;

    let (res, reqs) = run_test_http_server(vec![], |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Missing);
    assert_eq!(reqs.len(), 0);
}

#[rstest]
#[tokio::test]
async fn test_check_card_authorized_with_cards() {
    let body = r#""{\"respCode\":\"0000\",\"respInfo\":\"成功\",\"objs\":[{\"acctNo\":12345,\"acctAmt\":1000,\"cardTypeName\":\"正式卡\"}]}""#;
    let replies = vec![http_reply("200 OK", body)];
    let session = session_with_card_grant();
    let s = &session;

    let (res, reqs) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/NcAccType/GetCurrentAccountList");
}

#[rstest]
#[tokio::test]
async fn test_check_card_authorized_with_empty_cards() {
    let body = r#""{\"respCode\":\"0000\",\"respInfo\":\"成功\",\"objs\":[]}""#;
    let replies = vec![http_reply("200 OK", body)];
    let session = session_with_card_grant();
    let s = &session;

    let (res, reqs) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
    assert_eq!(reqs.len(), 1);
}

#[rstest]
#[tokio::test]
async fn test_check_card_authorized_with_direct_json_envelope() {
    let body = r#"{"respCode":"0000","respInfo":"成功","objs":[]}"#;
    let replies = vec![http_reply("200 OK", body)];
    let session = session_with_card_grant();
    let s = &session;

    let (res, reqs) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
    assert_eq!(reqs.len(), 1);
}

#[rstest]
#[tokio::test]
async fn test_check_card_envelope_missing_objs_is_model_parse() {
    let body = r#""{\"respCode\":\"0000\",\"respInfo\":\"成功\"}""#;
    let replies = vec![http_reply("200 OK", body)];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::ModelParse { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_card_envelope_scalar_objs_is_model_parse() {
    let body = r#""{\"respCode\":\"0000\",\"respInfo\":\"成功\",\"objs\":\"scalar\"}""#;
    let replies = vec![http_reply("200 OK", body)];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::ModelParse { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_card_unauthorized_401() {
    let replies = vec![http_reply("401 Unauthorized", "unauthorized")];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Unauthorized);
}

#[rstest]
#[tokio::test]
async fn test_check_card_unauthorized_403() {
    let replies = vec![http_reply("403 Forbidden", "forbidden")];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Unauthorized);
}

#[rstest]
#[tokio::test]
async fn test_check_card_business_error_is_website_without_leak() {
    let body =
        r#""{\"respCode\":\"1001\",\"respInfo\":\"sensitive internal message\",\"objs\":null}""#;
    let replies = vec![http_reply("200 OK", body)];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    match res {
        Err(ApiError::Website { msg }) => {
            assert!(!msg.contains("1001"));
            assert!(!msg.contains("sensitive internal message"));
        }
        other => panic!("expected Website error, got {other:?}"),
    }
}

#[rstest]
#[tokio::test]
async fn test_check_card_server_error_500_is_http_status() {
    let replies = vec![http_reply("500 Internal Server Error", "server crash")];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert!(matches!(
        res,
        Err(ApiError::HttpStatus { status }) if status == StatusCode::INTERNAL_SERVER_ERROR
    ));
}

#[rstest]
#[tokio::test]
async fn test_check_card_malformed_response_is_model_parse() {
    let replies = vec![http_reply("200 OK", "<html>Not JSON</html>")];
    let session = session_with_card_grant();
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert!(matches!(res, Err(ApiError::ModelParse { .. })));
}

#[rstest]
#[tokio::test]
async fn test_check_card_independent_of_is_login() {
    let body = r#""{\"respCode\":\"0000\",\"respInfo\":\"成功\",\"objs\":[]}""#;
    let replies = vec![http_reply("200 OK", body)];
    let mut session = session_with_card_grant();
    session.is_login = false;
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
    assert!(!session.is_login());
}

#[rstest]
#[tokio::test]
async fn test_check_card_connection_failure_distinct_from_unauthorized() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client = Client::custom(|b| b.resolve("card.cqu.edu.cn", addr)).unwrap();
    let session = session_with_card_grant();

    let res = check_card_authorization(&client, &session).await;

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
async fn test_restored_independent_card_grant() {
    let body = r#""{\"respCode\":\"0000\",\"respInfo\":\"成功\",\"objs\":[]}""#;
    let replies = vec![http_reply("200 OK", body)];
    let mut initial = Session::new();
    initial.access_infos.card_access_info = Some(CardAccessInfo {
        synjones_auth: None,
    });
    let snapshot = initial.export_snapshot().unwrap();
    let session = Session::from_snapshot(&snapshot).unwrap();
    assert!(!session.is_login());
    let s = &session;

    let (res, _) = run_test_http_server(replies, |client| async move {
        check_card_authorization(&client, s).await
    })
    .await;

    assert_eq!(res.unwrap(), ServiceAuthorizationStatus::Authorized);
}
