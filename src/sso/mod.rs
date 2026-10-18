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
    sso::tools::{get_login_request_data, launch_login_data, launch_second_factor_data},
    utils::{
        consts::{
            SSO_CAPTCHA_URL, SSO_LOGIN_URL, SSO_LOGOUT_URL, SSO_MAIL_BINDING_URL,
            SSO_PHONE_BINDING_URL, SSO_SEND_MAIL_CODE_URL, SSO_SEND_SMS_CODE_URL,
        },
        get_response_header,
        page_parser::{SSOLoginPageData, sso_login_parser},
    },
};
pub(crate) mod pending;
pub use pending::{
    PendingLoginStatus, PendingSecondFactorStatus, cancel_pending_login, pending_captcha_image,
    pending_login_status, resume_login, send_pending_second_factor_code, start_login,
    submit_pending_second_factor,
};

mod encrypt;
mod status;
#[cfg(test)]
pub(crate) mod tests;
pub(crate) mod tools;

/// 退出账号登陆
pub async fn logout(client: &Client, session: &mut Session) -> SSOResult<()> {
    session
        .execute(client.get(SSO_LOGOUT_URL))
        .await
        .map_err(|_| SSOError::LogoutError)?;
    session.is_login = false;
    session.pending_login = None;
    session.access_infos = Default::default();

    Ok(())
}

/// 获取与当前会话绑定的登录验证码图片
pub async fn captcha_image(client: &Client, session: &Session) -> SSOResult<Vec<u8>> {
    let res = session.execute(client.get(SSO_CAPTCHA_URL)).await?;
    let status = res.status();
    let bytes = res.bytes().await?.to_vec();

    if !status.is_success() {
        return Err(ApiError::HttpStatus { status });
    }
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(ApiError::ModelParse {
            msg: "Captcha response is not a valid PNG image".to_string(),
        });
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
#[derive(Clone, Eq, PartialEq)]
pub struct SecondFactorInfo {
    /// 手机号（脱敏，用于前端展示）
    pub phone: Option<String>,
    /// 短信绑定 token 或完整发送目标
    pub phone_token: Option<String>,
    /// 邮箱（发送目标）
    pub email: Option<String>,
    /// 验证流程标识
    pub execution: String,
}

impl std::fmt::Debug for SecondFactorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondFactorInfo")
            .field("phone", &self.phone)
            .field("has_phone_token", &self.phone_token.is_some())
            .field("email", &self.email.as_deref().map(mask_email))
            .field("has_execution", &(!self.execution.is_empty()))
            .finish()
    }
}

pub(crate) fn mask_email(email: &str) -> String {
    let email = email.trim();
    if let Some((user, domain)) = email.split_once('@') {
        let mut chars = user.chars();
        match (chars.next(), chars.last()) {
            (Some(first), Some(last)) => format!("{first}***{last}@{domain}"),
            (Some(first), None) => format!("{first}***@{domain}"),
            _ => "***".to_string(),
        }
    } else {
        "***".to_string()
    }
}

pub(crate) fn mask_phone(phone: &str) -> String {
    let phone = phone.trim();
    if phone.contains('*') {
        phone.to_string()
    } else {
        let char_count = phone.chars().count();
        if char_count == 11 {
            let first3: String = phone.chars().take(3).collect();
            let last4: String = phone.chars().skip(7).collect();
            format!("{first3}****{last4}")
        } else if char_count >= 7 {
            let first3: String = phone.chars().take(3).collect();
            let last4: String = phone.chars().skip(char_count - 4).collect();
            format!("{first3}****{last4}")
        } else {
            "***".to_string()
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum LoginResponseOutcome {
    Success,
    IncorrectCredentials {
        fresh_page: Option<SSOLoginPageData>,
    },
    CaptchaRequired {
        page: SSOLoginPageData,
    },
    SecondFactorRequired {
        info: Box<SecondFactorInfo>,
    },
}

async fn login_page_outcome(
    client: &Client,
    session: &Session,
    page: SSOLoginPageData,
) -> SSOResult<LoginResponseOutcome> {
    let is_second_factor = page.sso_second != "false"
        && (matches!(page.sso_second.as_str(), "true" | "smsLogin" | "mailLogin")
            || page.current_login_type == "smsLogin"
            || page.current_login_type == "mailLogin"
            || !page.phone_number.is_empty()
            || !page.user_email.is_empty());

    if is_second_factor {
        let has_ssr_phone = !page.phone_number.trim().is_empty();
        let has_ssr_email = !page.user_email.trim().is_empty();
        let ssr_phone_is_masked = page.phone_number.contains('*');
        let ssr_email_is_masked = page.user_email.contains('*');

        let need_phone_lookup = !has_ssr_phone || ssr_phone_is_masked;
        let need_email_lookup = !has_ssr_email || ssr_email_is_masked;

        let (phone_token, display_phone, email) = if !need_phone_lookup && !need_email_lookup {
            let display_phone = Some(mask_phone(&page.phone_number));
            (
                Some(page.phone_number),
                display_phone,
                Some(page.user_email),
            )
        } else {
            if page.user_object_id.is_empty() {
                return Err(SSOError::SecondFactorError {
                    msg: "Second-factor page has no user-object-id".to_string(),
                }
                .into());
            }

            let (phone_token, display_phone) = if need_phone_lookup {
                let phone_resp =
                    lookup_binding(client, session, SSO_PHONE_BINDING_URL, &page.user_object_id)
                        .await?;
                let token = parse_binding(phone_resp.data, SecondFactorKind::Sms)?;
                let display = if has_ssr_phone {
                    Some(mask_phone(&page.phone_number))
                } else {
                    None
                };
                (token, display)
            } else {
                let display = Some(mask_phone(&page.phone_number));
                (Some(page.phone_number), display)
            };

            let email = if need_email_lookup {
                let email_resp =
                    lookup_binding(client, session, SSO_MAIL_BINDING_URL, &page.user_object_id)
                        .await?;
                parse_binding(email_resp.data, SecondFactorKind::Mail)?
            } else {
                Some(page.user_email)
            };

            (phone_token, display_phone, email)
        };

        let info = SecondFactorInfo {
            phone: display_phone,
            phone_token,
            email,
            execution: page.login_page_flowkey,
        };
        if info.phone_token.is_none() && info.email.is_none() {
            return Err(SSOError::NoSecondFactorBindings.into());
        }
        Ok(LoginResponseOutcome::SecondFactorRequired {
            info: Box::new(info),
        })
    } else if !page.captcha_url.is_empty() {
        Ok(LoginResponseOutcome::CaptchaRequired { page })
    } else {
        Ok(LoginResponseOutcome::IncorrectCredentials {
            fresh_page: Some(page),
        })
    }
}

async fn lookup_binding(
    client: &Client,
    session: &Session,
    url: &str,
    user_id: &str,
) -> SSOResult<SendCodeResponse> {
    let payload = serde_json::json!({ "userId": user_id });
    let res = session.execute(client.post(url).json(&payload)).await?;
    if !res.status().is_success() {
        return Err(ApiError::HttpStatus {
            status: res.status(),
        });
    }
    let body = res.text().await?;
    parse_second_factor_response(&body, "binding lookup")
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
            return Err(ApiError::ModelParse {
                msg: format!("Invalid {kind:?} binding response structure"),
            });
        }
    };
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let value = value.trim();
            Ok((!value.is_empty()).then(|| value.to_owned()))
        }
        _ => Err(ApiError::ModelParse {
            msg: format!("Invalid {kind:?} binding value type"),
        }),
    }
}
pub(crate) fn bound_contact(info: &SecondFactorInfo, kind: SecondFactorKind) -> SSOResult<&str> {
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

pub(crate) async fn handle_login_response_internal(
    client: &Client,
    session: &mut Session,
    res: Response,
) -> SSOResult<LoginResponseOutcome> {
    session.is_login = false;
    match res.status() {
        StatusCode::FOUND => {
            let location =
                get_response_header(&res, "Location").ok_or_else(ApiError::location_error)?;
            let url = res.url().join(location).map_err(|_| ApiError::Website {
                msg: "Invalid login redirect URL".to_string(),
            })?;
            status::validate_login_redirect(res.url(), &url)?;

            if status::is_exact_cas_success_callback(&url) {
                let confirmation = session.execute(client.get(SSO_LOGIN_URL)).await?;
                match confirmation.status() {
                    StatusCode::FOUND => {
                        let confirm_loc = get_response_header(&confirmation, "Location")
                            .ok_or_else(ApiError::location_error)?;
                        let confirm_target =
                            confirmation.url().join(confirm_loc).map_err(|_| {
                                ApiError::Website {
                                    msg: "Invalid login confirmation redirect URL".to_string(),
                                }
                            })?;
                        status::validate_login_redirect(confirmation.url(), &confirm_target)?;
                        ensure!(
                            status::is_exact_cas_success_callback(&confirm_target),
                            errors::WebsiteSnafu {
                                msg: "Login confirmation redirected to unexpected target",
                            }
                        );
                        session.is_login = true;
                        return Ok(LoginResponseOutcome::Success);
                    }
                    StatusCode::OK => {
                        let html = confirmation.text().await?;
                        session.set_ruishu_challenge_from_page(&html);
                        if let Some(page) = sso_login_parser(&html) {
                            return login_page_outcome(client, session, page).await;
                        }
                        return Err(ApiError::Website {
                            msg: "Login redirect did not establish an authenticated CAS session"
                                .to_string(),
                        });
                    }
                    other => {
                        return Err(ApiError::HttpStatus { status: other });
                    }
                }
            }

            let landing = session.execute(client.get(url.clone())).await?;
            if landing.status().is_success() {
                let html = landing.text().await?;
                session.set_ruishu_challenge_from_page(&html);
                if let Some(page) = sso_login_parser(&html) {
                    return login_page_outcome(client, session, page).await;
                }
            } else if landing.status() == StatusCode::FOUND {
                let loc2 = get_response_header(&landing, "Location")
                    .ok_or_else(ApiError::location_error)?;
                let url2 = landing.url().join(loc2).map_err(|_| ApiError::Website {
                    msg: "Invalid secondary SSO redirect URI format".to_string(),
                })?;
                ensure!(
                    url2 != *res.url() && url2 != url,
                    errors::WebsiteSnafu {
                        msg: "SSO redirect cycle detected",
                    }
                );
                status::validate_login_redirect(landing.url(), &url2)?;
                if !status::is_exact_cas_success_callback(&url2) {
                    let second_landing = session.execute(client.get(url2)).await?;
                    if second_landing.status().is_success() {
                        let html = second_landing.text().await?;
                        session.set_ruishu_challenge_from_page(&html);
                        if let Some(page) = sso_login_parser(&html) {
                            return login_page_outcome(client, session, page).await;
                        }
                    } else {
                        return Err(ApiError::HttpStatus {
                            status: second_landing.status(),
                        });
                    }
                }
            } else {
                return Err(ApiError::Website {
                    msg: format!("Login landing returned HTTP {}", landing.status()),
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
            session.is_login = true;
            Ok(LoginResponseOutcome::Success)
        }
        StatusCode::UNAUTHORIZED => {
            let text = res.text().await?;
            session.set_ruishu_challenge_from_page(&text);
            match sso_login_parser(&text) {
                Some(page) => login_page_outcome(client, session, page).await,
                None => Ok(LoginResponseOutcome::IncorrectCredentials { fresh_page: None }),
            }
        }
        StatusCode::OK => {
            let html = res.text().await?;
            session.set_ruishu_challenge_from_page(&html);
            let page = sso_login_parser(&html).ok_or(ApiError::ModelParse {
                msg: "Failed to parse re-rendered login page".to_string(),
            })?;
            login_page_outcome(client, session, page).await
        }
        other => Err(ApiError::HttpStatus { status: other }),
    }
}

async fn handle_login_response(
    client: &Client,
    session: &mut Session,
    res: Response,
) -> SSOResult<LoginResult> {
    let outcome = handle_login_response_internal(client, session, res).await?;
    Ok(match outcome {
        LoginResponseOutcome::Success => LoginResult::Success,
        LoginResponseOutcome::IncorrectCredentials { .. } => LoginResult::IncorrectLoginCredentials,
        LoginResponseOutcome::CaptchaRequired { .. } => LoginResult::CaptchaRequired,
        LoginResponseOutcome::SecondFactorRequired { info, .. } => {
            LoginResult::SecondFactorRequired(info)
        }
    })
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
    session.pending_login = None;
    session.access_infos = Default::default();
    let request_data = get_login_request_data(client, session, force_relogin).await?;

    match request_data {
        None => {
            session.is_login = true;
            Ok(LoginResult::Success)
        }

        Some(login_page_data) => {
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
    session.pending_login = None;
    session.access_infos = Default::default();
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
        return Err(ApiError::HttpStatus { status });
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
    let resp: SendCodeResponse = serde_json::from_str(body).map_err(|_| ApiError::ModelParse {
        msg: format!("{method} returned an invalid JSON response"),
    })?;
    if resp.code != Some(200) {
        let code = resp
            .code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "none".to_string());
        return Err(SSOError::SecondFactorError {
            msg: format!("{method} rejected with code {code}"),
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
