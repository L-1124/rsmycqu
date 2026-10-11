//! 重庆大学单点登录（SSO）相关模块

use reqwest::{Response, StatusCode};
use snafu::ensure;

use crate::{
    errors,
    errors::{
        ApiError,
        sso::{SSOError, SSOResult},
    },
    session::{Client, Session},
    sso::tools::{
        LoginPageResponse, get_login_request_data, launch_login_data, launch_second_factor_data,
    },
    utils::{
        consts::{
            SSO_CAPTCHA_URL, SSO_LOGIN_URL, SSO_LOGOUT_URL, SSO_MAIL_BINDING_URL,
            SSO_PHONE_BINDING_URL, SSO_SEND_MAIL_CODE_URL, SSO_SEND_SMS_CODE_URL,
        },
        get_response_header,
        page_parser::{SSOLoginPageData, sso_login_parser},
    },
};
mod encrypt;
mod tools;

#[cfg(test)]
mod tests;

/// 退出账号登陆
pub async fn logout(client: &Client, session: &mut Session) -> SSOResult<()> {
    session
        .execute(client.get(SSO_LOGOUT_URL))
        .await
        .map_err(|_| SSOError::LogoutError)?;
    session.is_login = false;

    Ok(())
}

/// 获取与当前会话绑定的登录验证码图片
pub async fn captcha_image(client: &Client, session: &Session) -> SSOResult<Vec<u8>> {
    let res = session.execute(client.get(SSO_CAPTCHA_URL)).await?;
    let status = res.status();
    let bytes = res.bytes().await?.to_vec();

    if status != StatusCode::OK || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(SSOError::UnknownSSOError {
            msg: format!(
                "captcha endpoint returned status {} with {} bytes (expected PNG image)",
                status,
                bytes.len()
            ),
        }
        .into());
    }

    Ok(bytes)
}

/// 登录结果
#[derive(Debug, Eq, PartialEq)]
pub enum LoginResult {
    /// 登录成功
    Success,

    /// 账号或密码错误
    IncorrectLoginCredentials,

    /// 服务端要求图形验证码
    CaptchaRequired,

    /// 需要二次身份验证（短信或邮件）
    SecondFactorRequired(Box<SecondFactorInfo>),
}
/// 二次身份验证通道（短信或邮件）
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SecondFactorKind {
    /// 短信验证码
    Sms,
    /// 邮箱验证码
    Mail,
}

impl SecondFactorKind {
    /// 返回站点登录表单的 `type` 值
    pub fn login_type(self) -> &'static str {
        match self {
            SecondFactorKind::Sms => "smsLogin",
            SecondFactorKind::Mail => "mailLogin",
        }
    }
}

/// 二次身份验证信息
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecondFactorInfo {
    /// 手机号
    pub phone: Option<String>,
    /// 短信绑定 token
    pub phone_token: Option<String>,
    /// 邮箱
    pub email: Option<String>,
    /// 验证流程标识
    pub execution: String,
}

async fn login_page_result(
    client: &Client,
    session: &Session,
    page: SSOLoginPageData,
) -> SSOResult<LoginResult> {
    let is_second_factor = page.sso_second != "false"
        && (matches!(page.sso_second.as_str(), "true" | "smsLogin" | "mailLogin")
            || page.current_login_type == "smsLogin"
            || page.current_login_type == "mailLogin"
            || !page.phone_number.is_empty()
            || !page.user_email.is_empty());

    if is_second_factor {
        if page.user_object_id.is_empty() {
            return Err(SSOError::SecondFactorError {
                msg: "Second-factor page has no user-object-id".to_string(),
            }
            .into());
        }
        let phone =
            lookup_binding(client, session, SSO_PHONE_BINDING_URL, &page.user_object_id).await?;
        let email =
            lookup_binding(client, session, SSO_MAIL_BINDING_URL, &page.user_object_id).await?;
        let info = SecondFactorInfo {
            phone: (!page.phone_number.is_empty()).then_some(page.phone_number),
            phone_token: parse_binding(phone.data, SecondFactorKind::Sms)?,
            email: parse_binding(email.data, SecondFactorKind::Mail)?,
            execution: page.login_page_flowkey,
        };
        if info.phone_token.is_none() && info.email.is_none() {
            return Err(SSOError::NoSecondFactorBindings.into());
        }
        Ok(LoginResult::SecondFactorRequired(Box::new(info)))
    } else if !page.captcha_url.is_empty() {
        Ok(LoginResult::CaptchaRequired)
    } else {
        Ok(LoginResult::IncorrectLoginCredentials)
    }
}

async fn lookup_binding(
    client: &Client,
    session: &Session,
    url: &str,
    user_id: &str,
) -> SSOResult<SendCodeResponse> {
    let (cipher, encrypted_key) = encrypt::BindingCipher::new()?;
    let payload = serde_json::json!({ "userId": user_id });
    let body = cipher.encrypt(payload.to_string().as_bytes());
    let res = session
        .execute(
            client
                .post(url)
                .header("content-type", "application/json")
                .header("hascrypto", "true")
                .header("privatekey", encrypted_key)
                .body(body),
        )
        .await?;
    ensure!(
        res.status().is_success(),
        errors::sso::SecondFactorSnafu {
            msg: format!("Binding lookup returned HTTP {}", res.status()),
        }
    );
    let body = res.text().await?;
    let decoded = if body.trim_start().starts_with('{') {
        body
    } else {
        cipher.decrypt(&body)?
    };
    parse_second_factor_response(&decoded, "binding lookup")
}

fn parse_binding(
    data: Option<serde_json::Value>,
    kind: SecondFactorKind,
) -> SSOResult<Option<String>> {
    use serde_json::Value;
    let value = match (kind, data) {
        (_, None | Some(Value::Null)) => return Ok(None),
        (SecondFactorKind::Sms, Some(Value::Object(mut data))) => data.remove("tel"),
        (SecondFactorKind::Mail, Some(value @ Value::String(_))) => Some(value),
        _ => {
            return Err(SSOError::SecondFactorError {
                msg: format!("Invalid {kind:?} binding response"),
            }
            .into());
        }
    };
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let value = value.trim();
            Ok((!value.is_empty()).then(|| value.to_owned()))
        }
        _ => Err(SSOError::SecondFactorError {
            msg: format!("Invalid {kind:?} binding value"),
        }
        .into()),
    }
}

fn bound_contact(info: &SecondFactorInfo, kind: SecondFactorKind) -> SSOResult<&str> {
    let phone = info
        .phone_token
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let email = info
        .email
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if phone.is_none() && email.is_none() {
        return Err(SSOError::NoSecondFactorBindings.into());
    }
    match kind {
        SecondFactorKind::Sms => phone.ok_or_else(|| SSOError::PhoneNotBound.into()),
        SecondFactorKind::Mail => email.ok_or_else(|| SSOError::EmailNotBound.into()),
    }
}

async fn handle_login_response(
    client: &Client,
    session: &mut Session,
    res: Response,
) -> SSOResult<LoginResult> {
    session.is_login = false;
    match res.status() {
        StatusCode::FOUND => {
            let location =
                get_response_header(&res, "Location").ok_or(ApiError::location_error())?;
            let url = res.url().join(location).map_err(|err| ApiError::Website {
                msg: format!("Invalid login redirect: {err}"),
            })?;
            let landing = session.execute(client.get(url)).await?;
            ensure!(
                landing.status().is_success(),
                errors::WebsiteSnafu {
                    msg: format!("Login landing returned HTTP {}", landing.status()),
                }
            );
            let html = landing.text().await?;
            session.set_ruishu_challenge_from_page(&html);
            if let Some(page) = sso_login_parser(&html) {
                return login_page_result(client, session, page).await;
            }
            let confirmation = session.execute(client.get(SSO_LOGIN_URL)).await?;
            ensure!(
                confirmation.status() == StatusCode::FOUND
                    && get_response_header(&confirmation, "Location").is_some(),
                errors::WebsiteSnafu {
                    msg: "Login redirect did not establish an authenticated CAS session",
                }
            );
            session.is_login = true;
            Ok(LoginResult::Success)
        }
        StatusCode::UNAUTHORIZED => Ok(LoginResult::IncorrectLoginCredentials),
        StatusCode::OK => {
            let html = res.text().await?;
            session.set_ruishu_challenge_from_page(&html);
            let page = sso_login_parser(&html).ok_or(ApiError::Website {
                msg: "Failed to parse re-rendered login page".to_string(),
            })?;
            login_page_result(client, session, page).await
        }
        other => Err(SSOError::UnknownSSOError {
            msg: format!("Unexpected status code: {}", other),
        }
        .into()),
    }
}

/// 登录账号
///
/// 返回 [`LoginResult::CaptchaRequired`] 时需调用 [`captcha_image`] 获取验证码并带码重试；
/// 返回 [`LoginResult::SecondFactorRequired`] 时需进行二次身份验证。
pub async fn login(
    client: &Client,
    session: &mut Session,
    auth: impl AsRef<str>,
    password: impl AsRef<str>,
    force_relogin: bool,
    captcha_code: Option<&str>,
) -> SSOResult<LoginResult> {
    let request_data = get_login_request_data(client, session, force_relogin).await?;

    match request_data {
        LoginPageResponse::HasLogin { login_url } => {
            session.is_login = false;
            let landing = session.execute(client.get(login_url)).await?;
            ensure!(
                landing.status().is_success(),
                errors::WebsiteSnafu {
                    msg: format!("Login landing returned HTTP {}", landing.status()),
                }
            );
            session.is_login = true;
            Ok(LoginResult::Success)
        }

        LoginPageResponse::NormalLogin { login_page_data } => {
            session.is_login = false;
            if !login_page_data.captcha_url.is_empty() && captcha_code.is_none() {
                return Ok(LoginResult::CaptchaRequired);
            }
            let login_data = launch_login_data(auth, password, &login_page_data, captcha_code)?;
            let res = session
                .execute(client.post(SSO_LOGIN_URL).form(&login_data))
                .await?;
            handle_login_response(client, session, res).await
        }
    }
}

/// 提交二次身份验证码（短信或邮箱验证码）
pub async fn submit_second_factor(
    client: &Client,
    session: &mut Session,
    auth: impl AsRef<str>,
    info: &SecondFactorInfo,
    kind: SecondFactorKind,
    code: impl AsRef<str>,
) -> SSOResult<LoginResult> {
    bound_contact(info, kind)?;
    let data = launch_second_factor_data(auth, code, kind.login_type(), &info.execution);
    let res = session
        .execute(client.post(SSO_LOGIN_URL).form(&data))
        .await?;

    handle_login_response(client, session, res).await
}

#[derive(serde::Serialize)]
pub(crate) struct SendSmsPayload<'a> {
    pub(crate) phone: &'a str,
    #[serde(rename = "businessNo")]
    pub(crate) business_no: &'a str,
}

#[derive(serde::Serialize)]
pub(crate) struct SendMailPayload<'a> {
    #[serde(rename = "type")]
    pub(crate) kind: &'a str,
    pub(crate) mbemail: &'a str,
    #[serde(rename = "businessNo")]
    pub(crate) business_no: &'a str,
}

#[derive(serde::Deserialize)]
struct SendCodeResponse {
    #[serde(default)]
    code: Option<u32>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

async fn handle_send_code_response(res: Response, method: &str) -> SSOResult<()> {
    let status = res.status();
    if status == StatusCode::PRECONDITION_FAILED {
        return Err(SSOError::RuishuError {
            msg: format!("{method} was blocked by Ruishu (HTTP 412)"),
        }
        .into());
    }

    if !status.is_success() {
        return Err(SSOError::SecondFactorError {
            msg: format!("{method} HTTP status {status}"),
        }
        .into());
    }

    let body = res.text().await?;
    let resp = parse_second_factor_response(&body, method)?;
    if resp
        .data
        .as_ref()
        .and_then(|data| data.get("result"))
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return Err(SSOError::SecondFactorError {
            msg: format!("{method} did not confirm sending the verification code"),
        }
        .into());
    }
    Ok(())
}

fn parse_second_factor_response(body: &str, method: &str) -> SSOResult<SendCodeResponse> {
    let resp: SendCodeResponse =
        serde_json::from_str(body).map_err(|err| SSOError::SecondFactorError {
            msg: format!("{method} returned an invalid JSON response: {err}"),
        })?;
    if resp.code != Some(200) {
        let err_msg = resp
            .data
            .as_ref()
            .and_then(|data| data.get("errorMessage"))
            .and_then(|value| value.as_str())
            .or(resp.message.as_deref())
            .unwrap_or("unknown error");
        return Err(SSOError::SecondFactorError {
            msg: format!("{method} failed with code {:?}: {err_msg}", resp.code),
        }
        .into());
    }
    Ok(resp)
}

async fn send_sms_code(
    client: &Client,
    session: &Session,
    phone: impl AsRef<str>,
) -> SSOResult<()> {
    let payload = SendSmsPayload {
        phone: phone.as_ref(),
        business_no: "0008",
    };
    let res = session
        .execute(client.post(SSO_SEND_SMS_CODE_URL).json(&payload))
        .await?;
    handle_send_code_response(res, "send_sms_code").await
}

async fn send_mail_code(
    client: &Client,
    session: &Session,
    email: impl AsRef<str>,
) -> SSOResult<()> {
    let payload = SendMailPayload {
        kind: "DEFAULT",
        mbemail: email.as_ref(),
        business_no: "2025031701",
    };
    let res = session
        .execute(client.post(SSO_SEND_MAIL_CODE_URL).json(&payload))
        .await?;
    handle_send_code_response(res, "send_mail_code").await
}

/// 发送指定通道的二次验证码。
///
/// 未绑定时返回 [`SSOError::PhoneNotBound`]、[`SSOError::EmailNotBound`]
/// 或 [`SSOError::NoSecondFactorBindings`]。
pub async fn send_second_factor_code(
    client: &Client,
    session: &Session,
    info: &SecondFactorInfo,
    kind: SecondFactorKind,
) -> SSOResult<()> {
    let contact = bound_contact(info, kind)?;
    match kind {
        SecondFactorKind::Sms => send_sms_code(client, session, contact).await,
        SecondFactorKind::Mail => send_mail_code(client, session, contact).await,
    }
}
#[cfg(any(feature = "mycqu", feature = "card"))]
/// 使用登陆了统一身份认证的账号获取指定服务许可
pub(super) async fn access_services(
    client: &Client,
    session: &Session,
    service: impl AsRef<str>,
) -> SSOResult<Response> {
    let res = session
        .execute(
            client
                .get(SSO_LOGIN_URL)
                .query(&[("service", service.as_ref())]),
        )
        .await?;

    ensure!(res.status() == StatusCode::FOUND, errors::NotLoginSnafu {});

    let jump_url = get_response_header(&res, "Location").ok_or(ApiError::location_error())?;

    Ok(session.execute(client.get(jump_url)).await?)
}
