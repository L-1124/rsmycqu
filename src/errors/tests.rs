use rstest::rstest;

use crate::{
    errors::{ApiError, DummyTestError},
    session::{Client, Session},
};

type TestApiError = ApiError<DummyTestError>;

#[rstest]
#[tokio::test]
async fn test_timeout_vs_network_isolated_loopback() {
    let client = Client::custom(|builder| {
        builder
            .no_proxy()
            .timeout(std::time::Duration::from_millis(50))
    })
    .expect("test client with short timeout");

    let session = Session::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            std::thread::sleep(std::time::Duration::from_millis(200));
            use std::io::Write;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });

    let res: Result<_, TestApiError> = session
        .execute(client.get(format!("http://{addr}/test")))
        .await
        .map_err(ApiError::from);

    let err = res.expect_err("should time out");
    assert!(
        err.is_timeout(),
        "timeout must be detected via is_timeout()"
    );
    assert!(
        !err.is_network(),
        "timeout must be strictly excluded from is_network()"
    );
    assert!(
        !err.is_model_parse(),
        "timeout must not be classified as model parse"
    );
    assert!(
        !err.is_auth_error(),
        "timeout must not be classified as auth error"
    );

    let _ = handle.join();
}

#[rstest]
#[tokio::test]
async fn test_connection_error_isolated_loopback_port_and_url_sanitization() {
    // Bind a listener on an ephemeral port, get its address, then drop it immediately to guarantee a closed port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let secret_token = "SECRET_TOKEN_QUERY_99999";
    let client = Client::custom(|builder| builder.no_proxy()).expect("test client");
    let session = Session::new();

    let url_with_secret = format!("http://{addr}/test?token={secret_token}&ticket=SECRET_TICKET");
    let res: Result<_, TestApiError> = session
        .execute(client.get(&url_with_secret))
        .await
        .map_err(ApiError::from);

    let err = res.expect_err("connection to closed port must fail");
    assert!(
        err.is_network(),
        "connection failure must be detected via is_network()"
    );
    assert!(
        !err.is_timeout(),
        "connection failure must not be classified as timeout"
    );
    assert!(
        !err.is_model_parse(),
        "connection failure must not be classified as model parse"
    );

    // Verify diagnostic formatting and source chain traversal NEVER leaks the secret query token
    let display_str = format!("{err}");
    let debug_str = format!("{err:?}");
    assert!(
        !display_str.contains(secret_token),
        "ApiError display must not contain secret token"
    );
    assert!(
        !debug_str.contains(secret_token),
        "ApiError debug must not contain secret token"
    );

    let mut current_source = std::error::Error::source(&err);
    while let Some(src) = current_source {
        assert!(
            !src.to_string().contains(secret_token),
            "source error chain must not contain secret token"
        );
        current_source = src.source();
    }
}

#[cfg(feature = "sso")]
#[rstest]
#[tokio::test]
async fn test_real_decode_response_with_secret_not_leaked_in_diagnostics() {
    use crate::sso::tests::{http_reply, run_test_tls_server};

    let secret_field_value = "SUPER_SECRET_PAYLOAD_VALUE_999";

    // Server returns 200 OK with a body where a field has wrong type containing a secret string
    let bad_json_body = format!(
        r#"{{"name":"John","id":"123","code":42,"role":"student","phoneNumber":{{"nested":"{secret_field_value}"}}}}"#
    );

    // Deserializing into a struct with mismatch:
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct ExpectStringCode {
        code: Vec<String>, // expects Vec, but body has number 42
    }

    let (decode_res, _) = run_test_tls_server(
        vec![http_reply("200 OK", &bad_json_body)],
        |client| async move {
            let session = Session::new();
            let res = session
                .execute(client.get("https://sso.cqu.edu.cn/authserver/test"))
                .await
                .map_err(TestApiError::from)?;
            res.json::<ExpectStringCode>()
                .await
                .map_err(TestApiError::from)
        },
    )
    .await;

    let err = decode_res.expect_err("decoding into wrong model structure must fail");
    assert!(
        err.is_model_parse(),
        "decode failure must be classified as is_model_parse()"
    );
    assert!(
        !err.is_network(),
        "decode failure must not be classified as network error"
    );
    assert!(
        !err.is_timeout(),
        "decode failure must not be classified as timeout"
    );

    // Verify Display, Debug, and error source traversal do not contain the secret payload value
    let display_str = format!("{err}");
    let debug_str = format!("{err:?}");
    assert!(
        !display_str.contains(secret_field_value),
        "decode error display must not leak secret payload value"
    );
    assert!(
        !debug_str.contains(secret_field_value),
        "decode error debug must not leak secret payload value"
    );

    let mut current_source = std::error::Error::source(&err);
    while let Some(src) = current_source {
        assert!(
            !src.to_string().contains(secret_field_value),
            "source error chain must not leak secret payload value"
        );
        current_source = src.source();
    }
}

#[cfg(feature = "mycqu")]
#[rstest]
#[tokio::test]
async fn test_mycqu_consumer_valid_empty_vs_401_vs_business_error() {
    use crate::{
        mycqu::{exam::Exam, score::Score},
        session::access_info::MyCQUAccessInfo,
        sso::tests::{http_reply, run_test_tls_server},
    };

    let mut session = Session::new();
    session.access_infos.mycqu_access_info = Some(MyCQUAccessInfo {
        auth_header: "valid-token".to_string(),
    });

    // 1. Valid empty scores query returns Ok(vec![]), NOT an error
    let valid_empty_score = r#"{"status":"success","data":{}}"#;
    let (res_empty_score, _) =
        run_test_tls_server(vec![http_reply("200 OK", valid_empty_score)], |client| {
            let s = session.clone();
            async move { Score::fetch_self(&client, &s, false).await }
        })
        .await;
    assert_eq!(
        res_empty_score.expect("valid empty score must succeed"),
        vec![],
        "valid empty data must produce empty vector"
    );

    // 2. 401 Unauthorized MUST return ApiError::NotAccess, NEVER an empty vector
    let auth_error_body = r#"{"status":"error","message":"token expired","data":[]}"#;
    let (res_401, _) = run_test_tls_server(
        vec![http_reply("401 Unauthorized", auth_error_body)],
        |client| {
            let s = session.clone();
            async move { Score::fetch_self(&client, &s, false).await }
        },
    )
    .await;
    assert!(
        matches!(res_401, Err(ApiError::NotAccess)),
        "401 response must return ApiError::NotAccess, never success empty vector"
    );

    // 3. Upstream 200 OK business error { status: "error", msg: "denied" } MUST return ApiError::Website, NEVER empty vector
    let biz_error_body = r#"{"status":"error","msg":"access denied","data":[]}"#;
    let (res_biz, _) = run_test_tls_server(vec![http_reply("200 OK", biz_error_body)], |client| {
        let s = session.clone();
        async move { Score::fetch_self(&client, &s, false).await }
    })
    .await;
    assert!(
        matches!(res_biz, Err(ApiError::Website { .. })),
        "status: error must fail with ApiError::Website, never success empty vector"
    );

    // 4. Exam fetch_all: valid empty returns Ok(vec![])
    let valid_empty_exam = r#"{"status":"success","data":[]}"#;
    let (res_exam_empty, _) =
        run_test_tls_server(vec![http_reply("200 OK", valid_empty_exam)], |client| {
            let s = session.clone();
            async move { Exam::fetch_all(&client, &s, "20201234").await }
        })
        .await;
    assert_eq!(
        res_exam_empty.expect("valid empty exam must succeed"),
        vec![]
    );

    // 5. Exam fetch_all: 403 Forbidden returns ApiError::NotAccess, NEVER empty vector
    let (res_exam_403, _) = run_test_tls_server(
        vec![http_reply("403 Forbidden", auth_error_body)],
        |client| {
            let s = session.clone();
            async move { Exam::fetch_all(&client, &s, "20201234").await }
        },
    )
    .await;
    assert!(matches!(res_exam_403, Err(ApiError::NotAccess)));

    // 6. Exam fetch_all: status: "error" with empty data returns ApiError::Website, NEVER empty vector
    let (res_exam_err, _) =
        run_test_tls_server(vec![http_reply("200 OK", biz_error_body)], |client| {
            let s = session.clone();
            async move { Exam::fetch_all(&client, &s, "20201234").await }
        })
        .await;
    assert!(matches!(res_exam_err, Err(ApiError::Website { .. })));

    // 7. Exam fetch_all: wrong-type data field (not an array) returns ApiError::ModelParse
    let malformed_exam = r#"{"status":"success","data":"not-an-array"}"#;
    let (res_exam_malformed, _) =
        run_test_tls_server(vec![http_reply("200 OK", malformed_exam)], |client| {
            let s = session.clone();
            async move { Exam::fetch_all(&client, &s, "20201234").await }
        })
        .await;
    assert!(matches!(
        res_exam_malformed,
        Err(ApiError::ModelParse { .. })
    ));
}

#[cfg(feature = "mycqu")]
#[rstest]
#[tokio::test]
async fn test_enroll_course_info_malformed_group_fails_model_parse() {
    use crate::{
        mycqu::enroll::EnrollCourseInfo,
        session::access_info::MyCQUAccessInfo,
        sso::tests::{http_reply, run_test_tls_server},
    };

    let mut session = Session::new();
    session.access_infos.mycqu_access_info = Some(MyCQUAccessInfo {
        auth_header: "valid-token".to_string(),
    });

    // 1. Group row with missing selectionArea must return ModelParse, NOT silently skipped
    let malformed_group = r#"{"status":"success","data":[{"courseVOList":[]}]}"#;
    let (res_malformed, _) =
        run_test_tls_server(vec![http_reply("200 OK", malformed_group)], |client| {
            let s = session.clone();
            async move { EnrollCourseInfo::fetch_all(&client, &s, true).await }
        })
        .await;
    assert!(
        matches!(res_malformed, Err(ApiError::ModelParse { .. })),
        "malformed group row must fail with ModelParse, not silently skipped"
    );

    // 2. Group row with scalar courseVOList must return ModelParse, NOT silently skipped
    let scalar_courses =
        r#"{"status":"success","data":[{"selectionArea":"AreaA","courseVOList":"not-array"}]}"#;
    let (res_scalar, _) =
        run_test_tls_server(vec![http_reply("200 OK", scalar_courses)], |client| {
            let s = session.clone();
            async move { EnrollCourseInfo::fetch_all(&client, &s, true).await }
        })
        .await;
    assert!(matches!(res_scalar, Err(ApiError::ModelParse { .. })));

    // 3. Valid empty data array returns Ok(empty HashMap)
    let valid_empty = r#"{"status":"success","data":[]}"#;
    let (res_valid, _) = run_test_tls_server(vec![http_reply("200 OK", valid_empty)], |client| {
        let s = session.clone();
        async move { EnrollCourseInfo::fetch_all(&client, &s, true).await }
    })
    .await;
    let map = res_valid.expect("valid empty enroll info must succeed");
    assert!(map.is_empty());
}

#[cfg(feature = "card")]
#[rstest]
#[tokio::test]
async fn test_card_consumer_valid_empty_vs_401_vs_business_error() {
    use crate::{
        card::Card,
        session::access_info::CardAccessInfo,
        sso::tests::{http_reply, run_test_http_server},
    };

    let mut session = Session::new();
    session.access_infos.card_access_info = Some(CardAccessInfo {
        synjones_auth: None,
    });

    let card = Card {
        id: 123456,
        amount: 1000,
        account_status: Some("正常".to_string()),
    };

    // 1. Valid empty bills query returns Ok(vec![]), NOT an error
    let valid_empty_bills = r#"{"respCode":"0000","respInfo":"success","rows":[]}"#;
    let (res_empty, _) =
        run_test_http_server(vec![http_reply("200 OK", valid_empty_bills)], |client| {
            let s = session.clone();
            let c = card.clone();
            async move {
                c.fetch_bill(&client, &s, "2023-01-01", "2023-01-02", 1, 10)
                    .await
            }
        })
        .await;
    assert_eq!(
        res_empty.expect("valid empty bills must succeed"),
        vec![],
        "valid empty bills must return empty vector"
    );

    // 2. 401 Unauthorized MUST return ApiError::NotAccess, NEVER an empty vector
    let auth_error_body = r#"{"respCode":"401","respInfo":"unauthorized","rows":[]}"#;
    let (res_401, _) = run_test_http_server(
        vec![http_reply("401 Unauthorized", auth_error_body)],
        |client| {
            let s = session.clone();
            let c = card.clone();
            async move {
                c.fetch_bill(&client, &s, "2023-01-01", "2023-01-02", 1, 10)
                    .await
            }
        },
    )
    .await;
    assert!(
        matches!(res_401, Err(ApiError::NotAccess)),
        "401 response must return ApiError::NotAccess, never success empty vector"
    );

    // 3. Upstream 200 OK business error with respCode != "0000" MUST return ApiError::Website, NEVER empty vector
    let biz_error_body = r#"{"respCode":"9999","respInfo":"account frozen","rows":[]}"#;
    let (res_biz, _) = run_test_http_server(vec![http_reply("200 OK", biz_error_body)], |client| {
        let s = session.clone();
        let c = card.clone();
        async move {
            c.fetch_bill(&client, &s, "2023-01-01", "2023-01-02", 1, 10)
                .await
        }
    })
    .await;
    assert!(
        matches!(res_biz, Err(ApiError::Website { .. })),
        "non-0000 respCode must fail with ApiError::Website, never success empty vector"
    );

    // 4. Missing required rows field MUST return ApiError::ModelParse
    let missing_rows = r#"{"respCode":"0000","respInfo":"success"}"#;
    let (res_missing, _) =
        run_test_http_server(vec![http_reply("200 OK", missing_rows)], |client| {
            let s = session.clone();
            let c = card.clone();
            async move {
                c.fetch_bill(&client, &s, "2023-01-01", "2023-01-02", 1, 10)
                    .await
            }
        })
        .await;
    assert!(matches!(res_missing, Err(ApiError::ModelParse { .. })));
}
