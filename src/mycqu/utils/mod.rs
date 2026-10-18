use reqwest::{RequestBuilder, Response, StatusCode};
use serde_json::{Map, Value};
use snafu::ensure;

use crate::{
    errors,
    errors::{ApiError, mycqu::MyCQUResult},
    session::{Client, Session},
};

pub(super) mod access;
pub(super) mod encrypt;

pub(crate) async fn mycqu_request_handler<T>(
    client: &Client,
    session: &Session,
    f: T,
) -> MyCQUResult<Response>
where
    T: FnOnce(&Client) -> RequestBuilder,
{
    let access_info = if let Some(access_info) = session.access_infos.mycqu_access_info.as_ref() {
        access_info
    } else {
        return Err(ApiError::NotAccess);
    };

    let res = session
        .execute(f(client).bearer_auth(access_info.auth_header.as_str()))
        .await?;

    if res.status() == StatusCode::UNAUTHORIZED || res.status() == StatusCode::FORBIDDEN {
        return Err(ApiError::NotAccess);
    }
    if !res.status().is_success() {
        return Err(ApiError::HttpStatus {
            status: res.status(),
        });
    }
    Ok(res)
}

/// 检查响应json的status字段是否为error，如果是则返回错误
pub(crate) fn check_website_response(res: &Map<String, Value>) -> MyCQUResult<()> {
    ensure!(
        res.get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "success"),
        errors::WebsiteSnafu {
            msg: "Upstream returned non-success response status".to_string(),
        }
    );

    Ok(())
}
