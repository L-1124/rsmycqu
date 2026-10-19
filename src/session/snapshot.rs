//! Session 版本化快照序列化与恢复实现。
//!
//! # 信任边界与安全说明
//! 快照数据是格式版本化的敏感 JSON 字符串，包含会话 Cookies 和服务访问凭据等敏感内容。
//! **快照数据未经密码学签名或完整性鉴权**；此格式专为受信的本地存储设计，
//! 无法防御拥有本地存储写权限的恶意篡改。
//!
//! 恢复快照时**不会**进行任何网络通信或在线有效性校验；快照中的 `is_login`
//! 仅作为调用方的本地状态提示，绝非远端会话仍在线的有效性凭据。
//! 部署期站点脚本（`mainjs`）不会被包含在快照中，需由宿主进程在必要时通过
//! [`Session::set_mainjs`] 重新注入。

use std::sync::{Arc, RwLock};

use cookie_store::CookieStore;
use serde::{Deserialize, Serialize};

use super::{
    RUISHU_MAINJS_ROOT, RuishuState, Session, access_info::AccessInfos,
    cookie_store::InternalCookieStore,
};
use crate::errors::session::SessionError;

/// 当前快照格式规范版本
pub const CURRENT_SNAPSHOT_VERSION: u32 = 1;

/// 会话快照内部 DTO
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionSnapshotData {
    /// 快照格式版本
    pub(crate) version: u32,
    /// 导出时启用的 crate 特性列表
    pub(crate) features: Vec<String>,
    /// 本地登录状态提示（非在线凭证保证）
    pub(crate) is_login: bool,
    /// 各服务访问信息（严格特性匹配）
    pub(crate) access_infos: AccessInfosSnapshot,
    /// 瑞数防护状态
    pub(crate) ruishu: RuishuSnapshot,
    /// 未过期 Cookies 列表
    pub(crate) cookies: Vec<cookie_store::Cookie<'static>>,
    /// 待完成认证也属于会话敏感状态；无 SSO 构建仅允许 null。
    pub(crate) pending_login: serde_json::Value,
}

/// 服务访问凭据快照
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessInfosSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mycqu: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) card: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) atrust: Option<serde_json::Value>,
}

/// 瑞数状态快照
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuishuSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) challenge: Option<RuishuChallengeSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) basearr: Option<String>,
    /// 页面记录的外层脚本地址；跨进程恢复后据此按需拉取脚本，无需重新登录
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mainjs_src: Option<String>,
}

/// 瑞数页面挑战快照
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuishuChallengeSnapshot {
    pub(crate) cd: String,
    pub(crate) nsd: u32,
}

impl Session {
    /// 导出当前会话的版本化快照 JSON 字符串。
    ///
    /// # 安全与信任边界
    /// 快照包含会话 Cookies 与各服务登录凭证等敏感信息，**未经密码学签名或认证**。
    /// 请仅将快照保存在受信的本地安全存储中。
    ///
    /// # 瑞数防护状态
    /// 快照会原子化保留已有的瑞数挑战（`cd`/`nsd`）与 `basearr` 密文对。
    /// **部署期站点外层脚本（`mainjs`）不会被导出**，恢复会话后如需在挑战变化时
    /// 重新计算 `basearr`，调用方需重新调用 [`Session::set_mainjs`]。
    ///
    /// # Cookies
    /// 仅保留所有未过期的 Cookies（包括 session cookies）；过期 Cookies 会被丢弃。
    pub fn export_snapshot(&self) -> Result<String, SessionError> {
        let mut features = Vec::new();
        if cfg!(feature = "sso") {
            features.push("sso".to_string());
        }
        if cfg!(feature = "mycqu") {
            features.push("mycqu".to_string());
        }
        if cfg!(feature = "card") {
            features.push("card".to_string());
        }
        if cfg!(feature = "atrust") {
            features.push("atrust".to_string());
        }
        if cfg!(feature = "blocking") {
            features.push("blocking".to_string());
        }

        let access_snapshot = AccessInfosSnapshot {
            mycqu: {
                #[cfg(feature = "mycqu")]
                {
                    self.access_infos
                        .mycqu_access_info
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|_| SessionError::SnapshotError {
                            msg: "failed to serialize mycqu access info".to_string(),
                        })?
                }
                #[cfg(not(feature = "mycqu"))]
                {
                    None
                }
            },
            card: {
                #[cfg(feature = "card")]
                {
                    self.access_infos
                        .card_access_info
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|_| SessionError::SnapshotError {
                            msg: "failed to serialize card access info".to_string(),
                        })?
                }
                #[cfg(not(feature = "card"))]
                {
                    None
                }
            },
            atrust: {
                #[cfg(feature = "atrust")]
                {
                    self.access_infos
                        .atrust_access_info
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|_| SessionError::SnapshotError {
                            msg: "failed to serialize atrust access info".to_string(),
                        })?
                }
                #[cfg(not(feature = "atrust"))]
                {
                    None
                }
            },
        };

        // 原子化收集瑞数状态
        let (ruishu_snapshot, cookies) = {
            let state = self
                .ruishu_state
                .read()
                .map_err(|_| SessionError::LockError {
                    msg: "ruishu_state read lock poisoned".to_string(),
                })?;
            let challenge = state
                .challenge
                .as_ref()
                .map(|(cd, nsd)| RuishuChallengeSnapshot {
                    cd: cd.clone(),
                    nsd: *nsd,
                });
            let basearr = state.basearr.as_deref().map(hex::encode);
            let mainjs_src = state.mainjs_src.as_ref().map(|u| u.to_string());
            let cookies = self.cookie_jar.export_unexpired()?;
            (
                RuishuSnapshot {
                    challenge,
                    basearr,
                    mainjs_src,
                },
                cookies,
            )
        };

        let pending_login = {
            #[cfg(feature = "sso")]
            {
                if let Some(state) = &self.pending_login {
                    state.validate(self.is_login, !self.access_infos.is_empty())?;
                }
                serde_json::to_value(&self.pending_login).map_err(|_| {
                    SessionError::SnapshotError {
                        msg: "failed to serialize pending authentication".to_string(),
                    }
                })?
            }
            #[cfg(not(feature = "sso"))]
            {
                serde_json::Value::Null
            }
        };

        let snapshot_data = SessionSnapshotData {
            version: CURRENT_SNAPSHOT_VERSION,
            features,
            is_login: self.is_login,
            access_infos: access_snapshot,
            ruishu: ruishu_snapshot,
            cookies,
            pending_login,
        };

        serde_json::to_string(&snapshot_data).map_err(|_| SessionError::SnapshotError {
            msg: "failed to serialize session snapshot to json".to_string(),
        })
    }

    /// 从快照 JSON 字符串恢复 `Session`。
    ///
    /// # 安全与信任边界
    /// 本方法不发起任何网络请求；恢复后的 `is_login` 仅为本地状态提示，
    /// 并非远端服务端会话有效性的保证。
    ///
    /// # 校验规则
    /// - 快照版本必须受当前代码支持（当前版本为 1），否则返回 [`SessionError::UnsupportedVersion`]。
    /// - 检查特性兼容性：如果快照中包含当前构建未启用的特性授权（如 mycqu / card / atrust），
    ///   或声明了未启用的特性，返回 [`SessionError::FeatureMismatch`]。
    /// - 数据完整性：结构损坏、格式异常或 `basearr` 长度不符合规范（非空、16 的整数倍且在限制内）时，
    ///   返回 [`SessionError::SnapshotError`]。错误信息中**绝不包含**任何敏感明文或载荷。
    /// - 过期 Cookies 即使存在于快照数据中也会被丢弃，绝不会复活。
    ///
    /// # 瑞数外层脚本
    /// 部署期脚本 `mainjs` 不包含在快照中。恢复后若挑战变更且需要重新生成 `basearr`，
    /// 请调用 [`Session::set_mainjs`]。
    pub fn from_snapshot(snapshot: &str) -> Result<Self, SessionError> {
        let data: SessionSnapshotData =
            serde_json::from_str(snapshot).map_err(|_| SessionError::SnapshotError {
                msg: "malformed or truncated snapshot JSON".to_string(),
            })?;

        if data.version != CURRENT_SNAPSHOT_VERSION {
            return Err(SessionError::UnsupportedVersion {
                version: data.version,
            });
        }

        for feat in &data.features {
            match feat.as_str() {
                "sso" => {
                    if !cfg!(feature = "sso") {
                        return Err(SessionError::FeatureMismatch {
                            msg: format!("snapshot requires feature '{feat}' which is not enabled"),
                        });
                    }
                }
                "mycqu" => {
                    if !cfg!(feature = "mycqu") {
                        return Err(SessionError::FeatureMismatch {
                            msg: format!("snapshot requires feature '{feat}' which is not enabled"),
                        });
                    }
                }
                "card" => {
                    if !cfg!(feature = "card") {
                        return Err(SessionError::FeatureMismatch {
                            msg: format!("snapshot requires feature '{feat}' which is not enabled"),
                        });
                    }
                }
                "atrust" => {
                    if !cfg!(feature = "atrust") {
                        return Err(SessionError::FeatureMismatch {
                            msg: format!("snapshot requires feature '{feat}' which is not enabled"),
                        });
                    }
                }
                "blocking" => {
                    if !cfg!(feature = "blocking") {
                        return Err(SessionError::FeatureMismatch {
                            msg: format!("snapshot requires feature '{feat}' which is not enabled"),
                        });
                    }
                }
                _ => {
                    return Err(SessionError::FeatureMismatch {
                        msg: "snapshot declares an unknown or unsupported feature".to_string(),
                    });
                }
            }
        }

        #[cfg(not(feature = "mycqu"))]
        if data.access_infos.mycqu.is_some() {
            return Err(SessionError::FeatureMismatch {
                msg: "snapshot contains mycqu authorization".to_string(),
            });
        }
        #[cfg(not(feature = "card"))]
        if data.access_infos.card.is_some() {
            return Err(SessionError::FeatureMismatch {
                msg: "snapshot contains card authorization".to_string(),
            });
        }
        #[cfg(not(feature = "atrust"))]
        if data.access_infos.atrust.is_some() {
            return Err(SessionError::FeatureMismatch {
                msg: "snapshot contains atrust authorization".to_string(),
            });
        }
        let access_infos = AccessInfos {
            #[cfg(feature = "mycqu")]
            mycqu_access_info: data
                .access_infos
                .mycqu
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| SessionError::SnapshotError {
                    msg: "invalid mycqu authorization structure".to_string(),
                })?,
            #[cfg(feature = "card")]
            card_access_info: data
                .access_infos
                .card
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| SessionError::SnapshotError {
                    msg: "invalid card authorization structure".to_string(),
                })?,
            #[cfg(feature = "atrust")]
            atrust_access_info: data
                .access_infos
                .atrust
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| SessionError::SnapshotError {
                    msg: "invalid atrust authorization structure".to_string(),
                })?,
        };

        let mainjs_src = match data.ruishu.mainjs_src {
            Some(src_str) => {
                let sso_base = reqwest::Url::parse(RUISHU_MAINJS_ROOT).map_err(|_| {
                    SessionError::SnapshotError {
                        msg: "failed to parse default sso root".to_string(),
                    }
                })?;
                let resolved =
                    sso_base
                        .join(&src_str)
                        .map_err(|_| SessionError::SnapshotError {
                            msg: "invalid mainjs script URL syntax in snapshot".to_string(),
                        })?;
                super::validate_script_url(&resolved).map_err(|_| SessionError::SnapshotError {
                    msg: "unsafe mainjs script URL in snapshot".to_string(),
                })?;
                Some(resolved)
            }
            None => None,
        };
        let challenge = data.ruishu.challenge.map(|c| (c.cd, c.nsd));
        let active_host = mainjs_src
            .as_ref()
            .and_then(|u| u.host_str().map(ToString::to_string))
            .or_else(|| {
                if challenge.is_some() {
                    Some("sso.cqu.edu.cn".to_string())
                } else {
                    None
                }
            });
        let basearr = match data.ruishu.basearr {
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str).map_err(|_| SessionError::SnapshotError {
                    msg: "invalid basearr hex encoding in snapshot".to_string(),
                })?;
                if bytes.is_empty()
                    || !bytes.len().is_multiple_of(16)
                    || bytes.len() > crate::session::ruishu::MAX_BASEARR_LEN
                {
                    return Err(SessionError::SnapshotError {
                        msg: format!(
                            "invalid basearr length in snapshot: expected non-empty multiple of 16 up to {}, got {}",
                            crate::session::ruishu::MAX_BASEARR_LEN,
                            bytes.len()
                        ),
                    });
                }
                Some(Arc::from(bytes.into_boxed_slice()))
            }
            None => None,
        };

        let ruishu_state = RuishuState {
            basearr,
            challenge,
            mainjs_src,
            active_host,
        };

        let cookie_store = CookieStore::from_cookies(
            data.cookies
                .into_iter()
                .map(Ok::<_, std::convert::Infallible>),
            false,
        )
        .map_err(|_| SessionError::SnapshotError {
            msg: "failed to populate cookie store from snapshot".to_string(),
        })?;
        #[cfg(feature = "sso")]
        let pending_login: Option<crate::sso::pending::PendingLoginState> = {
            let pending: Option<crate::sso::pending::PendingLoginState> =
                serde_json::from_value(data.pending_login).map_err(|_| {
                    SessionError::SnapshotError {
                        msg: "invalid pending authentication structure".to_string(),
                    }
                })?;
            if let Some(state) = &pending {
                state.validate(data.is_login, !access_infos.is_empty())?;
            }
            pending
        };
        #[cfg(not(feature = "sso"))]
        if !data.pending_login.is_null() {
            return Err(SessionError::FeatureMismatch {
                msg: "snapshot contains pending SSO authentication".to_string(),
            });
        }

        Ok(Session {
            cookie_jar: Arc::new(InternalCookieStore::from_store(cookie_store)),
            is_login: data.is_login,
            access_infos,
            #[cfg(feature = "sso")]
            pending_login,
            ruishu_state: Arc::new(RwLock::new(ruishu_state)),
            ruishu_mainjs: Arc::new(RwLock::new(None)),
        })
    }
}
