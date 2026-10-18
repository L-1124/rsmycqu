use reqwest::{RequestBuilder, Response, StatusCode};

use crate::{
    errors::{ApiError, card::CardResult},
    session::{Client, Session},
};

pub(crate) async fn card_request_handler<T>(
    client: &Client,
    session: &Session,
    f: T,
) -> CardResult<Response>
where
    T: FnOnce(&Client) -> RequestBuilder,
{
    if session.access_infos.card_access_info.is_none() {
        return Err(ApiError::NotAccess);
    }

    let res = session.execute(f(client)).await?;

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

/// 解析校园卡后端返回的 JSON 信封（支持外层直接为 JSON 对象或嵌套在 JSON 字符串中的情形）
pub(crate) fn parse_card_envelope(
    raw_text: &str,
) -> CardResult<serde_json::Map<String, serde_json::Value>> {
    let parsed_val: serde_json::Value =
        serde_json::from_str(raw_text).map_err(|_| ApiError::ModelParse {
            msg: "Card response JSON format incorrect".to_string(),
        })?;

    let envelope: serde_json::Map<String, serde_json::Value> = match parsed_val {
        serde_json::Value::String(s) => match serde_json::from_str(&s) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => {
                return Err(ApiError::ModelParse {
                    msg: "Inner card JSON envelope format incorrect".to_string(),
                });
            }
        },
        serde_json::Value::Object(map) => map,
        _ => {
            return Err(ApiError::ModelParse {
                msg: "Card response envelope format incorrect".to_string(),
            });
        }
    };

    if envelope.get("respCode").and_then(serde_json::Value::as_str) == Some("0000") {
        Ok(envelope)
    } else {
        Err(ApiError::Website {
            msg: "Card upstream returned non-success response code".to_string(),
        })
    }
}
