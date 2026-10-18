//! 跨命令认证续接；所有站点请求显式接收同一个 Session。

use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    LoginResponseOutcome, SecondFactorInfo, SecondFactorKind, bound_contact,
    handle_login_response_internal, mask_email,
    tools::{get_login_request_data, launch_login_data, launch_second_factor_data},
};
use crate::{
    errors::{
        session::SessionError,
        sso::{SSOError, SSOResult},
    },
    session::{Client, Session},
    utils::{consts::SSO_LOGIN_URL, page_parser::SSOLoginPageData},
};

/// 待完成流程的本地最长存活时间；不是服务端有效期保证。
pub const DEFAULT_PENDING_TTL_SECS: u64 = 300;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 不含内部 token、execution 或原始联系方式的认证状态。
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PendingLoginStatus {
    /// 本地记录登录已完成；恢复快照后仍需业务请求验证在线有效性。
    Completed,
    /// 需要获取图形验证码并重新提供密码。
    CaptchaRequired,
    /// 凭据被拒绝，但服务端提供了可重试的新表单。
    CredentialRetry,
    /// 需要短信或邮箱验证码。
    SecondFactor(PendingSecondFactorStatus),
    /// 超过本地认证流程有效期。
    Expired,
    /// 请求结果或服务端流程不再确定，必须重新启动认证。
    Invalidated,
}

/// 二次验证的可选通道及脱敏联系方式。
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PendingSecondFactorStatus {
    /// 是否可发送短信验证码。
    pub sms_available: bool,
    /// 服务端返回的脱敏手机号。
    pub masked_phone: Option<String>,
    /// 是否可发送邮件验证码。
    pub mail_available: bool,
    /// 脱敏邮箱地址。
    pub masked_email: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingLoginState {
    account: String,
    expires_at: u64,
    stage: PendingStage,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum PendingStage {
    Password {
        page: Box<SSOLoginPageData>,
    },
    SecondFactor {
        #[serde(
            serialize_with = "SecondFactorSnapshot::serialize",
            deserialize_with = "deserialize_second_factor"
        )]
        info: Box<SecondFactorInfo>,
    },
    Invalidated,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "SecondFactorInfo", deny_unknown_fields)]
struct SecondFactorSnapshot {
    phone: Option<String>,
    phone_token: Option<String>,
    email: Option<String>,
    execution: String,
}

fn deserialize_second_factor<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Box<SecondFactorInfo>, D::Error> {
    SecondFactorSnapshot::deserialize(deserializer).map(Box::new)
}

impl PendingLoginState {
    pub(crate) fn validate(&self, is_login: bool, has_access: bool) -> Result<(), SessionError> {
        if now() >= self.expires_at {
            return Err(SessionError::ExpiredAuthentication);
        }
        let valid_stage = match &self.stage {
            PendingStage::Password { page } => {
                !page.login_page_flowkey.trim().is_empty()
                    && base64::Engine::decode(
                        &crate::utils::encrypt::BASE64PURPOSE,
                        &page.login_croypto,
                    )
                    .is_ok_and(|key| !key.is_empty() && key.len() <= 16)
            }
            PendingStage::SecondFactor { info } => {
                !info.execution.trim().is_empty()
                    && (info
                        .phone_token
                        .as_deref()
                        .is_some_and(|v| !v.trim().is_empty())
                        || info.email.as_deref().is_some_and(|v| !v.trim().is_empty()))
            }
            PendingStage::Invalidated => true,
        };
        if self.account.trim().is_empty() || is_login || has_access || !valid_stage {
            return Err(SessionError::SnapshotError {
                msg: "inconsistent pending authentication state".to_string(),
            });
        }
        Ok(())
    }

    fn status(&self) -> PendingLoginStatus {
        if now() >= self.expires_at {
            return PendingLoginStatus::Expired;
        }
        match &self.stage {
            PendingStage::Password { page } if !page.captcha_url.is_empty() => {
                PendingLoginStatus::CaptchaRequired
            }
            PendingStage::Password { .. } => PendingLoginStatus::CredentialRetry,
            PendingStage::SecondFactor { info } => {
                PendingLoginStatus::SecondFactor(PendingSecondFactorStatus {
                    sms_available: info.phone_token.is_some(),
                    masked_phone: info.phone.as_ref().map(|phone| {
                        if phone.contains('*') {
                            phone.clone()
                        } else {
                            "***".to_string()
                        }
                    }),
                    mail_available: info.email.is_some(),
                    masked_email: info.email.as_deref().map(mask_email),
                })
            }
            PendingStage::Invalidated => PendingLoginStatus::Invalidated,
        }
    }
}

fn active_state(session: &Session) -> SSOResult<&PendingLoginState> {
    let state = session
        .pending_login
        .as_ref()
        .ok_or(SSOError::PendingLoginNotStarted)?;
    if now() >= state.expires_at {
        return Err(SSOError::PendingLoginExpired.into());
    }
    if matches!(state.stage, PendingStage::Invalidated) {
        return Err(SSOError::PendingLoginInvalidated {
            msg: "Authentication execution is no longer confirmed".to_string(),
        }
        .into());
    }
    Ok(state)
}

/// 查询本地认证阶段，不访问网络，也不输出内部 token 或 execution。
pub fn pending_login_status(session: &Session) -> SSOResult<PendingLoginStatus> {
    if let Some(state) = &session.pending_login {
        Ok(state.status())
    } else if session.is_login() {
        Ok(PendingLoginStatus::Completed)
    } else {
        Err(SSOError::PendingLoginNotStarted.into())
    }
}

fn apply_outcome(
    session: &mut Session,
    outcome: LoginResponseOutcome,
) -> SSOResult<PendingLoginStatus> {
    let stage = match outcome {
        LoginResponseOutcome::Success => {
            session.pending_login = None;
            return Ok(PendingLoginStatus::Completed);
        }
        LoginResponseOutcome::IncorrectCredentials {
            fresh_page: Some(page),
        }
        | LoginResponseOutcome::CaptchaRequired { page } => PendingStage::Password {
            page: Box::new(page),
        },
        LoginResponseOutcome::IncorrectCredentials { fresh_page: None } => {
            PendingStage::Invalidated
        }
        LoginResponseOutcome::SecondFactorRequired { info, .. } => {
            PendingStage::SecondFactor { info }
        }
    };
    let state = session
        .pending_login
        .as_mut()
        .ok_or(SSOError::PendingLoginNotStarted)?;
    state.stage = stage;
    Ok(state.status())
}

/// 为指定账号启动认证，并将待完成状态保存在 Session 中。
///
/// 总是重新认证，清除旧服务授权，避免将已有 CAS 身份误认为传入账号。
/// 不保存密码；后续调用 resume_login 时需再次提供密码。
/// Session 的克隆共享 Cookie，认证期间不得并发复用这些克隆。
///
/// # Examples
///
/// ```no_run
/// use rsmycqu::{
///     errors::sso::SSOResult,
///     session::{Client, Session},
///     sso::start_login,
/// };
///
/// async fn begin(client: &Client, account: &str, password: &str) -> SSOResult<String> {
///     let mut session = Session::new();
///     start_login(client, &mut session, account, password).await?;
///     Ok(session.export_snapshot()?)
/// }
/// ```
pub async fn start_login(
    client: &Client,
    session: &mut Session,
    auth: impl AsRef<str>,
    password: impl AsRef<str>,
) -> SSOResult<PendingLoginStatus> {
    let account = auth.as_ref();
    if account.trim().is_empty() {
        return Err(SSOError::InvalidPendingState {
            msg: "Account cannot be empty".to_string(),
        }
        .into());
    }
    session.is_login = false;
    session.access_infos = Default::default();
    session.pending_login = None;
    let page = match get_login_request_data(client, session, true).await? {
        Some(page) => page,
        None => {
            return Err(SSOError::PendingLoginInvalidated {
                msg: "Cannot reuse an existing CAS identity".to_string(),
            }
            .into());
        }
    };
    let needs_captcha = !page.captcha_url.is_empty();
    session.pending_login = Some(PendingLoginState {
        account: account.to_owned(),
        expires_at: now().saturating_add(DEFAULT_PENDING_TTL_SECS),
        stage: PendingStage::Password {
            page: Box::new(page),
        },
    });
    if needs_captcha {
        pending_login_status(session)
    } else {
        resume_login(client, session, password, None).await
    }
}

/// 获取当前待完成流程的验证码图片，不重新初始化登录页。
pub async fn pending_captcha_image(client: &Client, session: &Session) -> SSOResult<Vec<u8>> {
    if !matches!(
        active_state(session)?.status(),
        PendingLoginStatus::CaptchaRequired
    ) {
        return Err(SSOError::InvalidPendingState {
            msg: "Current stage does not require an image captcha".to_string(),
        }
        .into());
    }
    super::captcha_image(client, session).await
}

/// 使用保存的表单与固定账号重试密码或图形验证码，不重新请求登录页。
///
/// 分发后的网络异常会使流程失效，避免重放结果未知的 execution。
pub async fn resume_login(
    client: &Client,
    session: &mut Session,
    password: impl AsRef<str>,
    captcha_code: Option<&str>,
) -> SSOResult<PendingLoginStatus> {
    let state = active_state(session)?;
    let PendingStage::Password { page } = &state.stage else {
        return Err(SSOError::InvalidPendingState {
            msg: "Current stage requires second-factor verification".to_string(),
        }
        .into());
    };
    if !page.captcha_url.is_empty() && captcha_code.is_none() {
        return Err(SSOError::InvalidPendingState {
            msg: "Captcha code is required".to_string(),
        }
        .into());
    }
    let form = launch_login_data(&state.account, password, page, captcha_code)?;
    session
        .pending_login
        .as_mut()
        .ok_or(SSOError::PendingLoginNotStarted)?
        .stage = PendingStage::Invalidated;
    let response = session
        .execute(client.post(SSO_LOGIN_URL).form(&form))
        .await?;
    let outcome = handle_login_response_internal(client, session, response).await?;
    apply_outcome(session, outcome)
}

/// 发送或重发当前待完成流程的二次验证码，不重置本地有效期。
pub async fn send_pending_second_factor_code(
    client: &Client,
    session: &Session,
    kind: SecondFactorKind,
) -> SSOResult<()> {
    let state = active_state(session)?;
    let PendingStage::SecondFactor { info } = &state.stage else {
        return Err(SSOError::InvalidPendingState {
            msg: "Current stage does not support second-factor delivery".to_string(),
        }
        .into());
    };
    super::send_second_factor_code(client, session, info, kind).await
}

/// 提交当前待完成流程的二次验证码；成功后清除内部认证上下文。
pub async fn submit_pending_second_factor(
    client: &Client,
    session: &mut Session,
    kind: SecondFactorKind,
    code: impl AsRef<str>,
) -> SSOResult<PendingLoginStatus> {
    let state = active_state(session)?;
    let PendingStage::SecondFactor { info } = &state.stage else {
        return Err(SSOError::InvalidPendingState {
            msg: "Current stage does not accept second-factor codes".to_string(),
        }
        .into());
    };
    bound_contact(info, kind)?;
    let form = launch_second_factor_data(&state.account, code, kind.login_type(), &info.execution);
    session
        .pending_login
        .as_mut()
        .ok_or(SSOError::PendingLoginNotStarted)?
        .stage = PendingStage::Invalidated;
    let response = session
        .execute(client.post(SSO_LOGIN_URL).form(&form))
        .await?;
    let outcome = handle_login_response_internal(client, session, response).await?;
    apply_outcome(session, outcome)
}

/// 清除本地待完成状态及服务授权；不向服务端登出，也不删除 Cookie。
pub fn cancel_pending_login(session: &mut Session) -> SSOResult<()> {
    session.pending_login = None;
    session.is_login = false;
    session.access_infos = Default::default();
    Ok(())
}
