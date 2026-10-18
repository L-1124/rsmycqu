//! 校园卡（card）在线授权有效性检查。

use reqwest::header::CONTENT_LENGTH;

use crate::{
    card::utils::{card_request_handler, parse_card_envelope},
    errors::{ApiError, card::CardResult},
    session::{Client, Session, access_info::ServiceAuthorizationStatus},
    utils::consts::CARD_GET_CARD_URL,
};

#[cfg(test)]
mod tests;

/// 检查当前会话持有的校园卡（`card.cqu.edu.cn`）授权在服务端的在线有效性。
///
/// 只读探测，不重新执行 SSO 授权，不修改会话内部授权信息。
/// 本地缺少授权信息时直接返回 [`Missing`][ServiceAuthorizationStatus::Missing]，不发起网络请求。
/// 仅校验校园卡基础服务在线授权，不代表宿舍水电费（Synjones）授权有效。
/// # 返回值
/// - [`Ok(ServiceAuthorizationStatus::Missing)`]：当前会话未持有校园卡服务授权。
/// - [`Ok(ServiceAuthorizationStatus::Authorized)`]：在线验证成功，授权有效且信封结构完整。
/// - [`Ok(ServiceAuthorizationStatus::Unauthorized)`]：服务端返回 HTTP 401/403 明确拒绝授权。
/// - [`Err`]：网络传输错误、超时、服务端 5xx 故障、信封格式不合法或业务错误响应。
pub async fn check_card_authorization(
    client: &Client,
    session: &Session,
) -> CardResult<ServiceAuthorizationStatus> {
    if session.access_infos.card_access_info.is_none() {
        return Ok(ServiceAuthorizationStatus::Missing);
    }

    let res = match card_request_handler(client, session, |client| {
        client.post(CARD_GET_CARD_URL).header(CONTENT_LENGTH, 0)
    })
    .await
    {
        Ok(res) => res,
        Err(ApiError::NotAccess) => return Ok(ServiceAuthorizationStatus::Unauthorized),
        Err(err) => return Err(err),
    };

    let raw_text = res.text().await?;
    let envelope = parse_card_envelope(&raw_text)?;
    // 严格校验信封规范：objs 必须为 JSON 数组（可为空数组 [] 代表无账户数据）
    match envelope.get("objs") {
        Some(serde_json::Value::Array(_)) => Ok(ServiceAuthorizationStatus::Authorized),
        _ => Err(ApiError::ModelParse {
            msg: "Card response envelope missing required 'objs' array".to_string(),
        }),
    }
}
