//! aTrust 登录和代理访问错误

use snafu::Snafu;

use crate::errors::{ApiResult, RsMyCQUError};

/// aTrust 接口错误
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ATrustError {
    /// 服务端返回的错误
    #[snafu(display("aTrust error {code}: {message}"))]
    Server {
        /// 服务端错误码
        code: i64,
        /// 服务端错误信息
        message: String,
    },
    /// 认证流程异常
    #[snafu(display("Unexpected aTrust flow: {message}"))]
    Flow {
        /// 错误原因
        message: String,
    },
}

impl RsMyCQUError for ATrustError {}

/// aTrust 接口的返回结果
pub type ATrustResult<T> = ApiResult<T, ATrustError>;
