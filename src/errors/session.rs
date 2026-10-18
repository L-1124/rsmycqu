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

    /// 会话内部状态锁已损坏
    #[snafu(display("Lock error: {msg}"))]
    LockError {
        /// 错误原因描述
        msg: String,
    },

    /// 快照格式错误、损坏或截断
    #[snafu(display("Snapshot error: {msg}"))]
    SnapshotError {
        /// 错误描述
        msg: String,
    },

    /// 快照版本不支持
    #[snafu(display("Unsupported snapshot version: {version}"))]
    UnsupportedVersion {
        /// 版本号
        version: u32,
    },

    /// 快照所需的特性在当前构建中缺失
    #[snafu(display("Feature mismatch: {msg}"))]
    FeatureMismatch {
        /// 缺失特性描述
        msg: String,
    },
}
