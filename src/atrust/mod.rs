//! aTrust CAS 登录和 Web 代理访问
//!
//! 启用 `atrust` feature 后使用，`sso` 会一并启用
//!
//! ```toml
//! rsmycqu = { version = "0.4", features = ["atrust"] }
//! ```
//!
//! 示例中的 [`Session`] 已完成 SSO 登录，或已导入有效的门户 Cookie
//!
//! ## 示例
//!
//! ```rust,no_run
//! use rsmycqu::{
//!     atrust::{access_application, access_atrust},
//!     session::{Client, Session, reqwest},
//! };
//!
//! async fn access_proxy(
//!     client: &Client,
//!     session: &mut Session,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     access_atrust(client, session).await?;
//!     let url = "https://lanunion-cqu-edu-cn.atrust.cqu.edu.cn/";
//!     access_application(client, session, url).await?;
//!
//!     let http = reqwest::Client::builder()
//!         .redirect(reqwest::redirect::Policy::none())
//!         .build()?;
//!     let response = session.execute(http.get(url)).await?;
//!     println!("{}", response.status());
//!     Ok(())
//! }
//! ```
//!
//! 本模块不支持 VPN 隧道和设备安全检测

use std::sync::LazyLock;

use regex::Regex;
use reqwest::{Response, Url};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::{Value, json};
use snafu::{ensure, whatever};

use crate::{
    errors::{
        self, ApiError,
        atrust::{ATrustError, ATrustResult},
    },
    session::{Client, Session, access_info::ATrustAccessInfo},
    sso::access_services,
};

/// aTrust 门户地址
pub const ATRUST_URL: &str = "https://atrust.cqu.edu.cn/";
/// aTrust CAS 回调地址
pub const ATRUST_CAS_SERVICE: &str =
    "https://atrust.cqu.edu.cn:443/passport/v1/auth/cas?sfDomain=CAS";

const CLIENT_QUERY: &[(&str, &str)] = &[
    ("clientType", "SDPBrowserClient"),
    ("platform", "Windows"),
    ("lang", "zh-CN"),
];
const MAX_HOPS: usize = 8;

#[derive(Deserialize)]
struct Envelope {
    code: i64,
    #[serde(default)]
    message: String,
    data: Value,
}

impl Envelope {
    fn into_data(self) -> ATrustResult<Value> {
        if self.code != 0 {
            return Err(ATrustError::Server {
                code: self.code,
                message: self.message,
            }
            .into());
        }
        Ok(self.data)
    }
}

fn flow(message: &str) -> ApiError<ATrustError> {
    ATrustError::Flow {
        message: message.to_owned(),
    }
    .into()
}

fn parse_url(value: &str) -> ATrustResult<Url> {
    Url::parse(value).map_err(|_| flow("Invalid URL"))
}

fn is_portal(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("atrust.cqu.edu.cn")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
}

fn is_application(url: &Url) -> bool {
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| host.ends_with(".atrust.cqu.edu.cn"))
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
}

fn http_redirect(response: &Response) -> ATrustResult<Option<Url>> {
    if !response.status().is_redirection() {
        return Ok(None);
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| flow("Redirect has no valid Location"))?;
    Ok(Some(
        response
            .url()
            .join(location)
            .map_err(|_| flow("Invalid redirect URL"))?,
    ))
}

async fn envelope(response: Response) -> ATrustResult<Envelope> {
    Ok(response.error_for_status()?.json().await?)
}

async fn config(client: &Client, session: &Session) -> ATrustResult<ATrustAccessInfo> {
    let response = session
        .execute(
            client
                .get("https://atrust.cqu.edu.cn/passport/v1/public/authConfig")
                .query(CLIENT_QUERY)
                .query(&[("mod", "1")]),
        )
        .await?;
    let data = envelope(response).await?.into_data()?;
    let token = data
        .pointer("/security/csrfToken")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| flow("authConfig has no CSRF token"))?;
    Ok(ATrustAccessInfo {
        csrf_token: token.to_owned(),
    })
}

fn is_online(data: &Value) -> bool {
    data.get("isOnline").and_then(Value::as_bool) == Some(true)
}

/// 登录 aTrust 门户，或恢复有效的门户 Cookie 会话
///
/// 没有有效的门户 Cookie 时，须先完成 [`crate::sso::login`] 和所需的二次验证
/// 处理 CAS 回调、`reportEnv` 和 `authCheck`
/// 网关要求本机客户端或其他验证时，返回错误
pub async fn access_atrust(client: &Client, session: &mut Session) -> ATrustResult<()> {
    session.access_infos.atrust_access_info = None;
    let existing_info = config(client, session).await?;
    let response = session
        .execute(
            client
                .get("https://atrust.cqu.edu.cn/passport/v1/user/onlineInfo")
                .query(CLIENT_QUERY)
                .header("x-csrf-token", &existing_info.csrf_token),
        )
        .await?;
    let online = envelope(response).await?;
    if online.code == 0 && is_online(&online.data) {
        session.access_infos.atrust_access_info = Some(existing_info);
        return Ok(());
    }
    // 仅错误码 75500002 表示未登录，其他服务端错误直接返回
    if online.code != 0 && online.code != 75500002 {
        online.into_data()?;
    }
    ensure!(session.is_login, errors::NotLoginSnafu {});

    let mut response = whatever!(
        access_services(client, session, ATRUST_CAS_SERVICE).await,
        "Failed to access aTrust CAS service"
    );
    let mut landed = false;
    for _ in 0..MAX_HOPS {
        if is_portal(response.url()) && response.url().path() == "/portal/shortcut.html" {
            landed = true;
            break;
        }
        let next = http_redirect(&response)?
            .filter(is_portal)
            .ok_or_else(|| flow("CAS did not reach aTrust shortcut"))?;
        response = session.execute(client.get(next)).await?;
    }
    if !landed {
        return Err(flow("Too many CAS redirects"));
    }
    response.error_for_status_ref()?;
    let landing = response
        .url()
        .query_pairs()
        .find_map(|(key, value)| (key == "data").then(|| value.into_owned()))
        .ok_or_else(|| flow("CAS shortcut has no authentication data"))?;
    let landing: Value = serde_json::from_str(&landing)
        .map_err(|_| flow("Invalid CAS shortcut authentication data"))?;
    let info = config(client, session).await?;
    if landing.pointer("/env/need").and_then(Value::as_bool) == Some(true) {
        let ticket = landing
            .get("ticket")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| flow("Missing environment ticket"))?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| flow("Could not generate device ID"))?;
        let device_id = hex::encode(random);
        let response = session
            .execute(
                client
                    .post("https://atrust.cqu.edu.cn/controller/v1/public/reportEnv")
                    .query(CLIENT_QUERY)
                    .header("x-csrf-token", &info.csrf_token)
                    .json(&json!({"ticket": ticket, "deviceId": device_id,
                "env": {"endpoint": {"device_id": device_id, "device": {"type": "browser"}}}})),
            )
            .await?;
        envelope(response).await?.into_data()?;
    }
    let response = session
        .execute(
            client
                .get("https://atrust.cqu.edu.cn/passport/v1/auth/authCheck")
                .query(CLIENT_QUERY)
                .header("x-csrf-token", &info.csrf_token),
        )
        .await?;
    let data = envelope(response).await?.into_data()?;
    if !data.get("onlineInfo").is_some_and(is_online)
        || data
            .get("nextService")
            .and_then(Value::as_str)
            .is_none_or(|next| !next.is_empty())
    {
        return Err(flow("aTrust requires an additional authentication step"));
    }
    session.access_infos.atrust_access_info = Some(info);
    Ok(())
}

fn script_redirect(html: &str, base: &Url) -> ATrustResult<Option<Url>> {
    static SCRIPT: LazyLock<Selector> = LazyLock::new(|| Selector::parse("script").unwrap());
    static LOCATION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"\bvar\s+locationUrl\s*=\s*("(?:[^"\\]|\\.)*")"#).unwrap());
    let document = Html::parse_document(html);
    for script in document.select(&SCRIPT) {
        for source in script.text() {
            if !source.contains("location.replace(") {
                continue;
            }
            if let Some(captures) = LOCATION.captures(source) {
                let location: String = serde_json::from_str(&captures[1])
                    .map_err(|_| flow("Invalid aTrust script redirect"))?;
                return Ok(Some(
                    base.join(&location)
                        .map_err(|_| flow("Invalid aTrust script redirect URL"))?,
                ));
            }
        }
    }
    Ok(None)
}

fn has_application_cookie(session: &Session, url: &Url) -> ATrustResult<bool> {
    Ok(session.cookies(url.clone())?.is_some_and(|cookies| {
        cookies.split(';').any(|cookie| {
            cookie
                .trim()
                .strip_prefix("sdp_user_token=")
                .is_some_and(|value| !value.is_empty())
        })
    }))
}

/// 获取代理应用的 `sdp_user_token` Cookie，保存到 [`Session`]
///
/// 调用前须先完成 [`access_atrust`]
/// `proxy_url` 须使用 HTTPS、443 端口和 `*.atrust.cqu.edu.cn` 域名
/// 例如：`https://lanunion-cqu-edu-cn.atrust.cqu.edu.cn/`
///
/// 只处理门户 `verify` 和目标应用之间的跳转，不执行 JavaScript
/// 业务系统可能还需要单独登录，后续请求使用 [`Session::execute`] 并检查 HTTP 状态
pub async fn access_application(
    client: &Client,
    session: &Session,
    proxy_url: impl AsRef<str>,
) -> ATrustResult<()> {
    ensure!(
        session.access_infos.atrust_access_info.is_some(),
        errors::NotAccessSnafu {}
    );
    let target = parse_url(proxy_url.as_ref())?;
    if !is_application(&target) {
        return Err(flow("Expected an aTrust HTTPS proxy application URL"));
    }
    let mut current = target.clone();
    for _ in 0..MAX_HOPS {
        let response = session.execute(client.get(current)).await?;
        let base = response.url().clone();
        let has_cookie = has_application_cookie(session, &target)?;
        if is_portal(&base) || !has_cookie {
            response.error_for_status_ref()?;
        }
        if base.query_pairs().any(|(key, _)| key == "sdpAppCode") && has_cookie {
            response.error_for_status_ref()?;
            return Ok(());
        }
        let next = if let Some(next) = http_redirect(&response)? {
            Some(next)
        } else if response.status().is_success()
            && response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.split(';').next() == Some("text/html"))
        {
            script_redirect(&response.text().await?, &base)?
        } else {
            None
        };
        let Some(next) = next else {
            if has_cookie {
                return Ok(());
            }
            return Err(flow("Proxy did not issue an application credential"));
        };
        let verify = is_portal(&next) && next.path() == "/controller/v1/public/verify";
        let application = is_application(&next) && next.origin() == target.origin();
        if !verify && !application {
            if has_cookie {
                return Ok(());
            }
            return Err(flow(
                "Proxy authentication redirected outside the application",
            ));
        }
        current = next;
    }
    Err(flow("Too many proxy authentication redirects"))
}

#[cfg(test)]
mod tests;
