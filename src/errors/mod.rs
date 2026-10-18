//! [`errors`]模块提供了[`rsmycqu`]的所有错误定义

use snafu::Snafu;

use crate::errors::sealed::Sealed;

pub mod session;

#[cfg(feature = "sso")]
pub mod sso;

#[cfg(feature = "mycqu")]
pub mod mycqu;

#[cfg(feature = "card")]
pub mod card;

mod sealed {
    #[cfg(feature = "sso")]
    use crate::errors::sso;

    pub trait Sealed {}

    #[cfg(feature = "sso")]
    impl Sealed for sso::SSOError {}

    #[cfg(feature = "mycqu")]
    impl Sealed for crate::errors::mycqu::MyCQUError {}

    #[cfg(feature = "card")]
    impl Sealed for crate::errors::card::CardError {}

    #[cfg(test)]
    impl Sealed for super::DummyTestError {}
}

#[cfg(test)]
#[derive(Debug, snafu::Snafu)]
#[snafu(display("dummy test error"))]
pub(crate) struct DummyTestError;

#[cfg(test)]
impl RsMyCQUError for DummyTestError {}

/// RsMyCQUError
pub trait RsMyCQUError: std::error::Error + 'static + Sealed {}

/// 错误类型
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ApiError<T: RsMyCQUError> {
    /// 当用户未登陆时抛出
    #[snafu(display("Request Before Login"))]
    NotLogin,

    /// 当用户未获取相应服务访问权限时抛出
    #[snafu(display("Request Before Get Access"))]
    NotAccess,

    /// 当Session构造失败时抛出
    #[snafu(display("Session Error: {source}"))]
    Session {
        /// Session错误
        source: session::SessionError,
    },

    /// 当使用[reqwest]发起的请求失败时抛出
    #[snafu(display("Reqwest Error: {source}"))]
    Request {
        /// [reqwest]抛出的错误[reqwest::Error]
        source: reqwest::Error,
    },

    /// 当请求返回未预期的 HTTP 状态码时抛出
    #[snafu(display("Unexpected HTTP status: {status}"))]
    HttpStatus {
        /// HTTP 状态码
        status: reqwest::StatusCode,
    },

    /// 数据模型解析异常时抛出
    #[snafu(display("Model Parse Error: {msg}"))]
    ModelParse {
        /// 错误信息
        msg: String,
    },

    /// 当请求网站出现异常时抛出
    #[snafu(display("Request Website Error: {msg}"))]
    Website {
        /// 错误详细信息
        msg: String,
    },

    /// 内部错误
    #[snafu(transparent)]
    Inner {
        /// 内部错误
        source: T,
    },

    /// 未知错误
    #[snafu(whatever)]
    Whatever {
        /// 错误信息
        message: String,
        /// 错误来源
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

#[allow(private_bounds)]
impl<T: RsMyCQUError> ApiError<T> {
    pub(crate) fn location_error() -> Self {
        ApiError::Website {
            msg: "Expected response has \"Location\" but not found".to_string(),
        }
    }

    /// 检查是否为网络超时错误
    pub fn is_timeout(&self) -> bool {
        match self {
            ApiError::Request { source } => source.is_timeout(),
            _ => false,
        }
    }

    /// 检查是否为网络连接或传输错误（排除超时、解析、重定向、请求构造或状态码错误）
    pub fn is_network(&self) -> bool {
        match self {
            ApiError::Request { source } => {
                !source.is_timeout()
                    && !source.is_decode()
                    && !source.is_builder()
                    && !source.is_redirect()
                    && !source.is_status()
                    && (source.is_connect() || source.is_request() || source.is_body())
            }
            _ => false,
        }
    }

    /// 检查是否为数据模型解析或解码错误
    pub fn is_model_parse(&self) -> bool {
        matches!(self, ApiError::ModelParse { .. })
    }

    /// 检查是否为认证或权限失效错误
    pub fn is_auth_error(&self) -> bool {
        matches!(self, ApiError::NotLogin | ApiError::NotAccess)
    }

    /// 获取关联的 HTTP 状态码（若存在）
    pub fn status_code(&self) -> Option<reqwest::StatusCode> {
        match self {
            ApiError::HttpStatus { status } => Some(*status),
            ApiError::Request { source } => source.status(),
            _ => None,
        }
    }
}

impl<T: RsMyCQUError> From<reqwest::Error> for ApiError<T> {
    fn from(source: reqwest::Error) -> Self {
        let sanitized = source.without_url();
        if sanitized.is_timeout() {
            ApiError::Request { source: sanitized }
        } else if sanitized.is_decode() {
            ApiError::ModelParse {
                msg: "Response body failed to deserialize into expected model".to_string(),
            }
        } else {
            ApiError::Request { source: sanitized }
        }
    }
}

impl<T: RsMyCQUError> From<session::SessionError> for ApiError<T> {
    fn from(source: session::SessionError) -> Self {
        match source {
            session::SessionError::Build { source: req_err } => ApiError::from(req_err),
            other => ApiError::Session { source: other },
        }
    }
}

/// API返回结果
pub type ApiResult<T, E> = Result<T, ApiError<E>>;

#[cfg(test)]
mod tests;
