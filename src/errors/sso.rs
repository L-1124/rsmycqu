//! 包含会在[`crate::sso`]中出现的所有错误

use std::fmt::Debug;

use snafu::prelude::*;

use crate::errors::{ApiResult, RsMyCQUError};

/// SSOError
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SSOError {
    /// 当加密密码错误时抛出
    #[snafu(display("Password Encrypt Error"))]
    PasswordEncryptError {
        /// 错误信息
        source: base64::DecodeError,
    },

    /// 登录页密码加密密钥为空或超过 AES 块长度
    #[snafu(display("Invalid login page password encryption key"))]
    InvalidPasswordKey,

    /// 当登出失败时抛出
    #[snafu(display("Logout Error"))]
    LogoutError,
    /// 瑞数保护参数解析或加解密错误
    #[snafu(display("Ruishu Error: {msg}"))]
    RuishuError {
        /// 错误原因描述
        msg: String,
    },

    /// 二次身份验证错误（如验证码错误、发送频繁等）
    #[snafu(display("Second factor error: {msg}"))]
    SecondFactorError {
        /// 错误原因描述
        msg: String,
    },
    /// 当前账号没有可用于二次验证的绑定
    #[snafu(display("Neither phone nor email is bound for second-factor authentication"))]
    NoSecondFactorBindings,
    /// 所选短信通道没有绑定手机号
    #[snafu(display("No phone is bound for second-factor authentication"))]
    PhoneNotBound,
    /// 所选邮件通道没有绑定邮箱
    #[snafu(display("No email is bound for second-factor authentication"))]
    EmailNotBound,
    /// 待完成认证已过期
    #[snafu(display("Pending login expired"))]
    PendingLoginExpired,
    /// 待完成认证处于无效或不可重试状态
    #[snafu(display("Pending login invalidated: {msg}"))]
    PendingLoginInvalidated {
        /// 失效原因
        msg: String,
    },
    /// 当前会话没有待完成的认证流程
    #[snafu(display("No pending authentication in this session"))]
    PendingLoginNotStarted,
    /// 待完成认证当前状态与所请求操作不匹配
    #[snafu(display("Invalid pending login state: {msg}"))]
    InvalidPendingState {
        /// 错误原因描述
        msg: String,
    },
    /// 由教务网引发的错误
    #[snafu(display("{msg}"))]
    UnknownSSOError {
        /// 教务网的预期返回和实际返回
        msg: String,
    },
}

impl RsMyCQUError for SSOError {}

/// SSOResult
pub type SSOResult<T> = ApiResult<T, SSOError>;
