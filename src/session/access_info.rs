//! 各模块支持服务所需的登陆信息

use serde::{Deserialize, Serialize};

/// 远程服务授权有效性状态
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServiceAuthorizationStatus {
    /// 本地缺少该服务的授权凭据（未曾获取或已清除）
    Missing,
    /// 经在线检查，服务端认可当前服务授权凭据有效
    Authorized,
    /// 经在线检查，服务端明确拒绝当前服务授权（如凭据已过期或被吊销，返回 401/403）
    Unauthorized,
}

/// [`mycqu`](crate::mycqu)所需的登陆信息
#[cfg(feature = "mycqu")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MyCQUAccessInfo {
    /// 该字符串应当添加进后续访问请求头的`Authorization`项中
    pub(crate) auth_header: String,
}

/// [`card`](crate::card)所需的登陆信息
#[cfg(feature = "card")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CardAccessInfo {
    /// 用于宿舍水电费查询的账号信息
    pub(crate) synjones_auth: Option<String>,
}

/// aTrust 门户的访问信息
#[cfg(feature = "atrust")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ATrustAccessInfo {
    pub(crate) csrf_token: String,
}

/// 包含各模块支持服务所需的登陆信息
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct AccessInfos {
    #[cfg(feature = "mycqu")]
    pub(crate) mycqu_access_info: Option<MyCQUAccessInfo>,
    #[cfg(feature = "card")]
    pub(crate) card_access_info: Option<CardAccessInfo>,
    #[cfg(feature = "atrust")]
    pub(crate) atrust_access_info: Option<ATrustAccessInfo>,
}

impl AccessInfos {
    /// 检查是否没有任何登录服务信息
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "mycqu")]
        if self.mycqu_access_info.is_some() {
            return false;
        }
        #[cfg(feature = "card")]
        if self.card_access_info.is_some() {
            return false;
        }
        #[cfg(feature = "atrust")]
        if self.atrust_access_info.is_some() {
            return false;
        }
        true
    }
}
