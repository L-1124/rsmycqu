//! SSO 在线会话有效性检查。

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{
        ApiError,
        sso::{SSOError, SSOResult},
    },
    session::{Client, Session},
    utils::{consts::SSO_LOGIN_URL, get_response_header, page_parser::sso_login_parser},
};

#[cfg(test)]
mod tests;

/// SSO 在线会话有效性状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SsoSessionStatus {
    /// 统一身份认证会话有效（已登录）。
    Authenticated,
    /// 统一身份认证会话无效（未登录）。
    Unauthenticated,
}

pub(super) fn is_cas_success_callback(target: &Url) -> bool {
    if target.scheme() != "https"
        || target.host_str() != Some("self.cqu.edu.cn")
        || target.port_or_known_default() != Some(443)
        || target.path() != "/cas-success"
        || target.fragment().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return false;
    }
    // CAS 成功跳转允许可选单值非空 ticket；不接受空值、重复或额外参数及 fragment
    match target.query() {
        None => true,
        Some(q) => {
            if q.contains('&') {
                return false;
            }
            let mut pairs = target.query_pairs();
            let first = pairs.next();
            if pairs.next().is_some() {
                return false;
            }
            match first {
                Some((key, val)) => key == "ticket" && !val.is_empty(),
                None => false,
            }
        }
    }
}

/// 校验统一身份认证跳转目标 URL 的安全性与合法性。
///
/// 准入规则：
/// 1. 同源跳转：`target` 与 `base` 具有相同的 scheme、host 和有效端口，且不含嵌入凭据。
/// 2. 特许回调重定向：当 `base` 处于标准 HTTPS 重大 SSO (`https://sso.cqu.edu.cn:443`) 时，
///    允许安全转移至确切的统一身份认证成功着陆页
///    (`https://self.cqu.edu.cn/cas-success`，标准 443 端口，无嵌入凭据、允许可选单值非空 ticket 参数、无 fragment)。
///
/// 其余任何跨域、降级（HTTP）、非常规端口、跨站伪造路径或携带多余 query/fragment 的跨源重定向均一律拒绝。
pub(super) fn validate_login_redirect(base: &Url, target: &Url) -> SSOResult<()> {
    if !target.username().is_empty() || target.password().is_some() {
        return Err(ApiError::Website {
            msg: "SSO redirect rejected: target contains embedded credentials".to_string(),
        });
    }

    let is_same_origin = target.scheme() == base.scheme()
        && target.host_str() == base.host_str()
        && target.port_or_known_default() == base.port_or_known_default();

    if is_same_origin {
        return Ok(());
    }

    let is_base_sso = base.scheme() == "https"
        && base.host_str() == Some("sso.cqu.edu.cn")
        && base.port_or_known_default() == Some(443);

    if is_base_sso && is_cas_success_callback(target) {
        return Ok(());
    }

    Err(ApiError::Website {
        msg: format!(
            "SSO redirect rejected: cross-origin redirect to {}",
            redirect_summary(target)
        ),
    })
}

/// 脱敏的跳转目标摘要：仅保留安全的 origin（scheme://host[:port]）与查询参数数量，
/// 避免在错误诊断中泄露可能包含敏感凭据的路径、查询键名或查询取值。
fn redirect_summary(target: &Url) -> String {
    let scheme = target.scheme();
    let host = target.host_str().unwrap_or("<unknown>");
    let origin = match target.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    let query_count = target.query_pairs().count();
    if query_count > 0 {
        format!("{origin}?[query: {query_count}]")
    } else {
        origin
    }
}

fn validate_redirect(base: &Url, target: &Url, visited: &[&Url]) -> SSOResult<()> {
    validate_login_redirect(base, target)?;
    if visited
        .iter()
        .any(|url| url.path() == target.path() && url.query() == target.query())
    {
        return Err(ApiError::Website {
            msg: "SSO redirect cycle detected".to_string(),
        });
    }
    Ok(())
}

async fn confirm_cas_authenticated(
    client: &Client,
    session: &Session,
) -> SSOResult<SsoSessionStatus> {
    let confirm_res = session.execute(client.get(SSO_LOGIN_URL)).await?;
    match confirm_res.status() {
        StatusCode::FOUND => {
            let loc = get_response_header(&confirm_res, "Location")
                .ok_or_else(ApiError::location_error)?;
            let target_url = confirm_res.url().join(loc).map_err(|_| ApiError::Website {
                msg: "Invalid SSO redirect URI format".to_string(),
            })?;
            validate_redirect(confirm_res.url(), &target_url, &[confirm_res.url()])?;
            Ok(SsoSessionStatus::Authenticated)
        }
        StatusCode::OK => {
            let html = confirm_res.text().await?;
            if sso_login_parser(&html).is_some() {
                Ok(SsoSessionStatus::Unauthenticated)
            } else {
                Err(ApiError::ModelParse {
                    msg: "SSO endpoint returned HTTP 200 OK without valid login page flowkey"
                        .to_string(),
                })
            }
        }
        other => Err(ApiError::HttpStatus { status: other }),
    }
}

/// 检查当前统一身份认证（SSO）会话在服务端的在线有效性。
///
/// 只读探测，不提交凭据，不发送验证码，不跟随不受信跨源重定向。
/// 若会话存在未完成的多步待办认证（[`session.pending_login`]），
/// 为避免干扰进行中的服务端 CAS 流程，直接返回 [`SSOError::InvalidPendingState`]。
/// # 返回值
/// - [`Ok(SsoSessionStatus::Authenticated)`]：会话在 SSO 系统的在线凭据确证有效（通过 CAS 重定向链与一致性状态确认）。
/// - [`Ok(SsoSessionStatus::Unauthenticated)`]：服务端返回结构可靠的登录页，确证当前未登录。
/// - [`Err`]：网络传输错误、超时、WAF 412 拦截、服务端 5xx 故障或无法解析的非预期响应。
pub async fn check_sso_session(client: &Client, session: &Session) -> SSOResult<SsoSessionStatus> {
    if session.pending_login.is_some() {
        return Err(SSOError::InvalidPendingState {
            msg: "cannot check online sso session while an active pending authentication is in progress".to_string(),
        }.into());
    }

    let res = session.execute(client.get(SSO_LOGIN_URL)).await?;

    match res.status() {
        StatusCode::OK => {
            let html = res.text().await?;
            if sso_login_parser(&html).is_some() {
                Ok(SsoSessionStatus::Unauthenticated)
            } else {
                Err(ApiError::ModelParse {
                    msg: "SSO endpoint returned HTTP 200 OK without valid login page flowkey"
                        .to_string(),
                })
            }
        }
        StatusCode::FOUND => {
            let location =
                get_response_header(&res, "Location").ok_or_else(ApiError::location_error)?;
            let redirect_url = res.url().join(location).map_err(|_| ApiError::Website {
                msg: "Invalid SSO redirect URI format".to_string(),
            })?;

            validate_redirect(res.url(), &redirect_url, &[res.url()])?;

            if is_cas_success_callback(&redirect_url) {
                return confirm_cas_authenticated(client, session).await;
            }

            let jump_res = session.execute(client.get(redirect_url)).await?;
            match jump_res.status() {
                StatusCode::FOUND => {
                    let loc2 = get_response_header(&jump_res, "Location")
                        .ok_or_else(ApiError::location_error)?;
                    let redirect_url2 =
                        jump_res.url().join(loc2).map_err(|_| ApiError::Website {
                            msg: "Invalid secondary SSO redirect URI format".to_string(),
                        })?;

                    validate_redirect(
                        jump_res.url(),
                        &redirect_url2,
                        &[res.url(), jump_res.url()],
                    )?;

                    let landing_res = session.execute(client.get(redirect_url2)).await?;
                    if landing_res.status().is_success() {
                        let html = landing_res.text().await?;
                        if sso_login_parser(&html).is_some() {
                            Ok(SsoSessionStatus::Unauthenticated)
                        } else {
                            confirm_cas_authenticated(client, session).await
                        }
                    } else if landing_res.status() == StatusCode::FOUND {
                        let loc3 = get_response_header(&landing_res, "Location")
                            .ok_or_else(ApiError::location_error)?;
                        let redirect_url3 =
                            landing_res
                                .url()
                                .join(loc3)
                                .map_err(|_| ApiError::Website {
                                    msg: "Invalid tertiary SSO redirect URI format".to_string(),
                                })?;
                        validate_redirect(
                            landing_res.url(),
                            &redirect_url3,
                            &[res.url(), jump_res.url(), landing_res.url()],
                        )?;
                        Err(ApiError::HttpStatus {
                            status: landing_res.status(),
                        })
                    } else {
                        Err(ApiError::HttpStatus {
                            status: landing_res.status(),
                        })
                    }
                }
                StatusCode::OK => {
                    let html = jump_res.text().await?;
                    if sso_login_parser(&html).is_some() {
                        Ok(SsoSessionStatus::Unauthenticated)
                    } else {
                        confirm_cas_authenticated(client, session).await
                    }
                }
                other => Err(ApiError::HttpStatus { status: other }),
            }
        }
        other => Err(ApiError::HttpStatus { status: other }),
    }
}
