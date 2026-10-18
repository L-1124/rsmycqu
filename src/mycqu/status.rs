//! 教务网（mycqu）在线授权有效性检查。

use crate::{
    errors::{ApiError, mycqu::MyCQUResult},
    mycqu::{User, utils::mycqu_request_handler},
    session::{Client, Session, access_info::ServiceAuthorizationStatus},
    utils::consts::MYCQU_API_USER_URL,
};

#[cfg(test)]
mod tests;

/// 检查当前会话持有的教务网（`my.cqu.edu.cn`）授权在服务端的在线有效性。
///
/// 只读探测，不重新执行 OAuth 授权，不修改会话内部授权信息。
/// 本地缺少授权信息时直接返回 [`Missing`][ServiceAuthorizationStatus::Missing]，不发起网络请求。
/// # 返回值
/// - [`Ok(ServiceAuthorizationStatus::Missing)`]：当前会话未持有教务网服务授权。
/// - [`Ok(ServiceAuthorizationStatus::Authorized)`]：在线验证成功，授权有效且响应模型字段完整。
/// - [`Ok(ServiceAuthorizationStatus::Unauthorized)`]：服务端返回 HTTP 401/403 明确拒绝授权。
/// - [`Err`]：网络传输错误、超时、服务端 5xx 故障或响应数据格式损坏。
pub async fn check_mycqu_authorization(
    client: &Client,
    session: &Session,
) -> MyCQUResult<ServiceAuthorizationStatus> {
    if session.access_infos.mycqu_access_info.is_none() {
        return Ok(ServiceAuthorizationStatus::Missing);
    }

    let res = match mycqu_request_handler(client, session, |client| client.get(MYCQU_API_USER_URL))
        .await
    {
        Ok(res) => res,
        Err(ApiError::NotAccess) => return Ok(ServiceAuthorizationStatus::Unauthorized),
        Err(err) => return Err(err),
    };

    let user: User = res.json().await?;

    if user.id.trim().is_empty() && user.code.trim().is_empty() {
        return Err(ApiError::ModelParse {
            msg: "mycqu user response contained empty identity fields".to_string(),
        });
    }

    Ok(ServiceAuthorizationStatus::Authorized)
}
