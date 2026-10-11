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
