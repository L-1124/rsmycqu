//! [Session]使用错误

use reqwest::Error as ReqwestError;
use snafu::prelude::*;

/// [Session]使用错误
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionError {
    #[snafu(transparent)]
    /// 由于`reqwest`错误导致的错误
    Build {
        /// 错误信息
        source: ReqwestError,
    },

    /// 瑞数防护参数解析或加解密错误
    #[snafu(display("Ruishu Error: {msg}"))]
    RuishuError {
        /// 错误原因描述
        msg: String,
    },
}
