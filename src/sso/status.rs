//! SSO 在线会话有效性检查。

use reqwest::Url;

use crate::errors::{ApiError, sso::SSOResult};

#[cfg(test)]
mod tests;

pub(super) fn is_exact_cas_success_callback(target: &Url) -> bool {
    target.scheme() == "https"
        && target.host_str() == Some("self.cqu.edu.cn")
        && target.port_or_known_default() == Some(443)
        && target.path() == "/cas-success"
        && target.query().is_none()
        && target.fragment().is_none()
        && target.username().is_empty()
        && target.password().is_none()
}

/// 校验统一身份认证跳转目标 URL 的安全性与合法性。
///
/// 准入规则：
/// 1. 同源跳转：`target` 与 `base` 具有相同的 scheme、host 和有效端口，且不含嵌入凭据。
/// 2. 特许回调重定向：当 `base` 处于标准 HTTPS 重大 SSO (`https://sso.cqu.edu.cn:443`) 时，
///    允许安全转移至确切的统一身份认证成功着陆页
///    (`https://self.cqu.edu.cn/cas-success`，标准 443 端口，无嵌入凭据、无 query、无 fragment)。
///
/// 其余任何跨域、降级（HTTP）、非常规端口、跨站伪造路径或携带 query/fragment 的跨源重定向均一律拒绝。
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

    if is_base_sso && is_exact_cas_success_callback(target) {
        return Ok(());
    }

    Err(ApiError::Website {
        msg: "SSO redirect rejected: cross-origin redirect".to_string(),
    })
}
