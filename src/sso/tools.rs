use reqwest::{Response, StatusCode};
use snafu::ensure;

use crate::{
    errors,
    errors::{ApiError, sso::SSOResult},
    session::{Client, Session},
    sso::{encrypt::encrypt_password, logout, status},
    utils::{
        consts::SSO_LOGIN_URL,
        get_response_header,
        page_parser::{SSOLoginPageData, sso_login_parser},
    },
};

async fn launch_normal_login_result(
    session: &Session,
    res: Response,
) -> SSOResult<Option<SSOLoginPageData>> {
    let html = res.text().await?;
    session.set_ruishu_challenge_from_page(&html);
    Ok(Some(sso_login_parser(&html).ok_or(
        ApiError::ModelParse {
            msg: "Failed to parse login page".to_string(),
        },
    )?))
}

/// 获取登陆请求所需数据。
///
/// 返回 [`Some(SSOLoginPageData)`] 表示需要提交账号凭据进行登录；
/// 返回 [`None`] 表示统一身份认证会话已确认为在线有效状态，无需重新提交登录表单。
pub(crate) async fn get_login_request_data(
    client: &Client,
    session: &mut Session,
    force_relogin: bool,
) -> SSOResult<Option<SSOLoginPageData>> {
    let res = session.execute(client.get(SSO_LOGIN_URL)).await?;
    match res.status() {
        StatusCode::FOUND => {
            if force_relogin {
                logout(client, session).await?;
                let local_res = session.execute(client.get(SSO_LOGIN_URL)).await?;
                return launch_normal_login_result(session, local_res).await;
            }

            let location =
                get_response_header(&res, "Location").ok_or_else(ApiError::location_error)?;
            let redirect_url = res.url().join(location).map_err(|_| ApiError::Website {
                msg: "Invalid login redirect URL".to_string(),
            })?;

            status::validate_login_redirect(res.url(), &redirect_url)?;

            if status::is_cas_success_callback(&redirect_url) {
                let confirmation = session.execute(client.get(SSO_LOGIN_URL)).await?;
                ensure!(
                    confirmation.status() == StatusCode::FOUND,
                    errors::WebsiteSnafu {
                        msg: "Login redirect did not establish an authenticated CAS session",
                    }
                );
                let confirm_loc = get_response_header(&confirmation, "Location")
                    .ok_or_else(ApiError::location_error)?;
                let confirm_target =
                    confirmation
                        .url()
                        .join(confirm_loc)
                        .map_err(|_| ApiError::Website {
                            msg: "Invalid login confirmation redirect URL".to_string(),
                        })?;
                status::validate_login_redirect(confirmation.url(), &confirm_target)?;
                ensure!(
                    status::is_cas_success_callback(&confirm_target),
                    errors::WebsiteSnafu {
                        msg: "Login confirmation redirected to unexpected target",
                    }
                );
                return Ok(None);
            }

            let landing_res = session.execute(client.get(redirect_url.clone())).await?;
            if landing_res.status().is_success() {
                let html = landing_res.text().await?;
                session.set_ruishu_challenge_from_page(&html);
                if let Some(page) = sso_login_parser(&html) {
                    return Ok(Some(page));
                }
            } else if landing_res.status() == StatusCode::FOUND {
                let loc2 = get_response_header(&landing_res, "Location")
                    .ok_or_else(ApiError::location_error)?;
                let redirect_url2 =
                    landing_res
                        .url()
                        .join(loc2)
                        .map_err(|_| ApiError::Website {
                            msg: "Invalid secondary SSO redirect URI format".to_string(),
                        })?;
                ensure!(
                    redirect_url2 != *res.url() && redirect_url2 != redirect_url,
                    errors::WebsiteSnafu {
                        msg: "SSO redirect cycle detected",
                    }
                );
                status::validate_login_redirect(landing_res.url(), &redirect_url2)?;
                if !status::is_cas_success_callback(&redirect_url2) {
                    let second_landing = session.execute(client.get(redirect_url2)).await?;
                    if second_landing.status().is_success() {
                        let html = second_landing.text().await?;
                        session.set_ruishu_challenge_from_page(&html);
                        if let Some(page) = sso_login_parser(&html) {
                            return Ok(Some(page));
                        }
                    } else {
                        return Err(ApiError::HttpStatus {
                            status: second_landing.status(),
                        });
                    }
                }
            } else {
                return Err(ApiError::HttpStatus {
                    status: landing_res.status(),
                });
            }

            let confirmation = session.execute(client.get(SSO_LOGIN_URL)).await?;
            ensure!(
                confirmation.status() == StatusCode::FOUND,
                errors::WebsiteSnafu {
                    msg: "Login redirect did not establish an authenticated CAS session",
                }
            );
            let confirm_loc = get_response_header(&confirmation, "Location")
                .ok_or_else(ApiError::location_error)?;
            let confirm_target =
                confirmation
                    .url()
                    .join(confirm_loc)
                    .map_err(|_| ApiError::Website {
                        msg: "Invalid login confirmation redirect URL".to_string(),
                    })?;
            status::validate_login_redirect(confirmation.url(), &confirm_target)?;
            Ok(None)
        }
        StatusCode::OK => launch_normal_login_result(session, res).await,
        other => Err(ApiError::HttpStatus { status: other }),
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
