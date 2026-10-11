use reqwest::{Response, StatusCode};

use crate::{
    errors::{
        ApiError,
        sso::{SSOError, SSOResult},
    },
    session::{Client, Session},
    sso::{encrypt::encrypt_password, logout},
    utils::{
        consts::SSO_LOGIN_URL,
        get_response_header,
        page_parser::{SSOLoginPageData, sso_login_parser},
    },
};

/// 登陆页面返回数据，根据该数据确定是否需要验证码或登陆链接
pub(super) enum LoginPageResponse {
    HasLogin { login_url: String },
    NormalLogin { login_page_data: SSOLoginPageData },
}

async fn launch_normal_login_result(
    session: &Session,
    res: Response,
) -> SSOResult<LoginPageResponse> {
    let html = res.text().await?;
    session.set_ruishu_challenge_from_page(&html);
    Ok(LoginPageResponse::NormalLogin {
        login_page_data: sso_login_parser(&html).ok_or(ApiError::Website {
            msg: "Failed to parse login page".to_string(),
        })?,
    })
}

/// 获取登陆请求所需数据
pub(super) async fn get_login_request_data(
    client: &Client,
    session: &mut Session,
    force_relogin: bool,
) -> SSOResult<LoginPageResponse> {
    let res = session.execute(client.get(SSO_LOGIN_URL)).await?;
    match res.status() {
        StatusCode::FOUND => {
            if force_relogin {
                logout(client, session).await?;
                let local_res = session.execute(client.get(SSO_LOGIN_URL)).await?;
                return launch_normal_login_result(session, local_res).await;
            }

            let jump_url =
                get_response_header(&res, "Location").ok_or(ApiError::location_error())?;

            let login_url_res = session.execute(client.get(jump_url)).await?;

            Ok(LoginPageResponse::HasLogin {
                login_url: get_response_header(&login_url_res, "Location")
                    .ok_or(ApiError::location_error())?
                    .to_string(),
            })
        }
        StatusCode::OK => launch_normal_login_result(session, res).await,
        other => Err(SSOError::UnknownSSOError {
            msg: format!(
                "status code {} is got (302 expected) when sending login post, \
            but can not find the element span.login_auth_error#msg",
                other
            )
            .to_string(),
        }
        .into()),
    }
}

#[inline]
pub(super) fn launch_login_data(
    username: impl AsRef<str>,
    password: impl AsRef<str>,
    login_page_data: &SSOLoginPageData,
    captcha_code: Option<&str>,
) -> SSOResult<Vec<(&'static str, String)>> {
    let mut data = vec![
        ("username", username.as_ref().to_owned()),
        ("type", "UsernamePassword".to_string()),
        ("_eventId", "submit".to_string()),
        ("geolocation", "".to_string()),
        ("execution", login_page_data.login_page_flowkey.to_owned()),
        ("croypto", login_page_data.login_croypto.to_owned()),
        (
            "password",
            encrypt_password(&login_page_data.login_croypto, password)?,
        ),
    ];

    if let Some(code) = captcha_code {
        data.push(("captcha_code", code.to_owned()));
        if !login_page_data.captcha_payload.is_empty() {
            data.push(("captcha_payload", login_page_data.captcha_payload.clone()));
        }
    }
    Ok(data)
}

#[inline]
pub(super) fn launch_second_factor_data(
    username: impl AsRef<str>,
    code: impl AsRef<str>,
    kind: impl AsRef<str>,
    execution: impl AsRef<str>,
) -> [(&'static str, String); 7] {
    [
        ("username", username.as_ref().to_owned()),
        ("password", code.as_ref().to_owned()),
        ("type", kind.as_ref().to_owned()),
        ("_eventId", "submit".to_string()),
        ("geolocation", "".to_string()),
        ("execution", execution.as_ref().to_owned()),
        ("captcha_code", "".to_string()),
    ]
}
