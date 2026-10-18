//! 在[`reqwest::Client`]的基础上增加了额外的状态以保证库运行正确性

use std::sync::{Arc, RwLock};

pub use client::Client;
pub use reqwest;
pub(crate) use reqwest::{IntoUrl, header};

use crate::{
    errors::session::SessionError,
    session::{access_info::AccessInfos, cookie_store::InternalCookieStore},
};

pub mod access_info;
mod client;
pub(crate) mod cookie_store;
pub mod ruishu;
pub(crate) mod snapshot;

pub use access_info::ServiceAuthorizationStatus;
pub use snapshot::CURRENT_SNAPSHOT_VERSION;
#[cfg(test)]
mod tests;

#[derive(Debug, Default)]
struct RuishuState {
    basearr: Option<Arc<[u8]>>,
    challenge: Option<(String, u32)>,
}

/// 发起校园信息请求的会话
///
/// [`Client`] 禁用自动重定向；Cookie 由会话独立管理。
#[derive(Clone)]
pub struct Session {
    cookie_jar: Arc<InternalCookieStore>,
    /// 是否已经通过[`sso`](crate::sso)登陆
    pub(crate) is_login: bool,
    /// 登陆后获取到的各服务访问信息
    pub(crate) access_infos: AccessInfos,
    #[cfg(feature = "sso")]
    pub(crate) pending_login: Option<crate::sso::pending::PendingLoginState>,
    // 挑战与内层密文在同一锁下更新，避免刷新时混用。
    ruishu_state: Arc<RwLock<RuishuState>>,
    /// 站点外层脚本，部署期固定；用于在会话尚未有 `basearr` 时纯算补出
    pub(crate) ruishu_mainjs: Arc<RwLock<Option<String>>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_challenge = self
            .ruishu_state
            .read()
            .map(|s| s.challenge.is_some())
            .unwrap_or(false);
        let has_basearr = self.basearr().is_some();
        let has_mainjs = self
            .ruishu_mainjs
            .read()
            .map(|m| m.is_some())
            .unwrap_or(false);
        let unexpired_cookies = self.cookie_jar.unexpired_count().unwrap_or(0);

        f.debug_struct("Session")
            .field("is_login", &self.is_login)
            .field("unexpired_cookies", &unexpired_cookies)
            .field("has_access_infos", &!self.access_infos.is_empty())
            .field("has_ruishu_challenge", &has_challenge)
            .field("has_basearr", &has_basearr)
            .field("has_mainjs", &has_mainjs)
            .finish()
    }
}

impl Session {
    /// 创建一个新的 `Session` 实例。
    pub fn new() -> Self {
        Session {
            cookie_jar: Arc::new(InternalCookieStore::new()),
            is_login: false,
            access_infos: AccessInfos::default(),
            #[cfg(feature = "sso")]
            pending_login: None,
            ruishu_state: Arc::new(RwLock::new(RuishuState::default())),
            ruishu_mainjs: Arc::new(RwLock::new(None)),
        }
    }

    /// 使用此会话的上下文（特别是Cookie）来执行一个HTTP请求。
    ///
    /// 发送前注入 Cookie；受保护请求缺少 Cookie T 且已有挑战材料时提前纯算；
    /// 遇 CQU 瑞数 412 且已有页面挑战时重算 Cookie T 并重发一次。
    /// 无法复制的请求体仍会发送，但不自动重试。
    ///
    /// # Arguments
    /// * `builder` - 一个由共享客户端创建的 `reqwest::RequestBuilder`。
    pub async fn execute(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, SessionError> {
        let (client, request) = builder.build_split();
        let mut request = request.map_err(|e| SessionError::Build {
            source: e.without_url(),
        })?;
        let mut retry_request = if is_cqu_host(request.url()) {
            request.try_clone()
        } else {
            None
        };

        loop {
            let mut cookie_header = self.cookie_jar.get_header_value(request.url())?;
            let (_, cookie_t_name) = ruishu_cookie_names(request.url());
            if is_cqu_host(request.url())
                && request.url().path().contains("protected")
                && !cookie_header
                    .as_ref()
                    .is_some_and(|h| has_cookie_t(h, cookie_t_name))
                && !request
                    .headers()
                    .get_all(header::COOKIE)
                    .iter()
                    .any(|h| has_cookie_t(h, cookie_t_name))
            {
                self.refresh_ruishu_cookie(request.url())?;
                cookie_header = self.cookie_jar.get_header_value(request.url())?;
            }
            if let Some(cookie_header) = cookie_header {
                request.headers_mut().append(header::COOKIE, cookie_header);
            }
            if is_cqu_host(request.url()) {
                if request.headers().get("sid-language").is_none() {
                    request.headers_mut().insert(
                        header::HeaderName::from_static("sid-language"),
                        header::HeaderValue::from_static("zh_CN"),
                    );
                }
                if request.url().path().contains("protected") {
                    let (key, value) = csrf_headers();
                    request.headers_mut().insert(CSRF_KEY_HEADER, key);
                    request.headers_mut().insert(CSRF_VALUE_HEADER, value);
                }
            }
            let response = client
                .execute(request)
                .await
                .map_err(|e| SessionError::Build {
                    source: e.without_url(),
                })?;
            let response_url = response.url();
            for cookie_str in response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
            {
                self.cookie_jar.add_cookie_str(cookie_str, response_url)?;
            }

            let Some(retry) = retry_request.take() else {
                return Ok(response);
            };
            if !is_ruishu_blocked(response_url, response.status()) {
                return Ok(response);
            }
            if !self.refresh_ruishu_cookie(response_url)? {
                return Ok(response);
            }
            request = retry;
        }
    }

    fn refresh_ruishu_cookie(&self, url: &reqwest::Url) -> Result<bool, SessionError> {
        let mut state = self
            .ruishu_state
            .write()
            .map_err(|_| SessionError::LockError {
                msg: "ruishu_state lock poisoned".to_string(),
            })?;
        let Some((cd, nsd)) = state.challenge.as_ref() else {
            return Ok(false);
        };
        let cookie_t = match &state.basearr {
            Some(basearr) => ruishu::refresh_cookie_t(cd, basearr.as_ref())?,
            None => {
                let mainjs_lock =
                    self.ruishu_mainjs
                        .read()
                        .map_err(|_| SessionError::LockError {
                            msg: "ruishu_mainjs lock poisoned".to_string(),
                        })?;
                let mainjs = mainjs_lock
                    .as_deref()
                    .ok_or_else(|| SessionError::RuishuError {
                        msg: "basearr missing and Session::set_mainjs was not called".to_string(),
                    })?;
                let (cookie_t, basearr) = ruishu::generate_cookie_t_auto(mainjs, *nsd, cd)?;
                state.basearr = Some(Arc::from(basearr.into_boxed_slice()));
                cookie_t
            }
        };
        let (_, cookie_t_name) = ruishu_cookie_names(url);
        self.cookie_jar
            .add_cookie_str(&format!("{cookie_t_name}={cookie_t}; Path=/"), url)?;
        Ok(true)
    }

    /// 向会话注入 Cookies（`name=value; name2=value2`），作用域由 `url` 的 host 决定
    ///
    /// `sso.cqu.edu.cn` 的 `/api/protected/*` 只校验 `CtLgrmkSWHBZO` 与 `CtLgrmkSWHBZP`
    /// 这一对 Cookies，且该对会随浏览器刷新作废；服务端返回 412 时需重新注入。
    pub fn set_cookies<U: IntoUrl>(&self, url: U, cookies: &str) -> Result<(), SessionError> {
        let url = url.into_url()?;

        for cookie in cookies.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            self.cookie_jar.add_cookie_str(cookie, &url)?;
        }

        Ok(())
    }

    /// 注入 CQU 瑞数防护 Cookie 对；SSO 使用 O/P，教务网使用 S/T。
    ///
    /// Cookie T 可用 [`ruishu::generate_cookie_t`] 纯算生成。
    pub fn set_ruishu_cookies<U: IntoUrl>(
        &self,
        url: U,
        cookie_o: &str,
        cookie_t: &str,
    ) -> Result<(), SessionError> {
        let url = url.into_url()?;
        let (server_name, client_name) = ruishu_cookie_names(&url);
        let cookies = format!("{server_name}={cookie_o}; {client_name}={cookie_t}");
        self.set_cookies(url, &cookies)
    }

    /// 获取会话对指定 `url` 会发送的 Cookie 头
    pub fn cookies<U: IntoUrl>(&self, url: U) -> Result<Option<String>, SessionError> {
        let url = url.into_url()?;

        self.cookie_jar.get_cookie_header(&url)
    }
    /// 注入当前挑战的内层密文，用于 412 时重建 Cookie T。
    ///
    /// ```
    /// # use rsmycqu::session::Session;
    /// let session = Session::new();
    /// session.set_basearr(&[0x5a; 160]).unwrap();
    /// assert_eq!(session.basearr().unwrap().len(), 160);
    /// ```
    pub fn set_basearr(&self, basearr: &[u8]) -> Result<(), SessionError> {
        if basearr.is_empty()
            || !basearr.len().is_multiple_of(16)
            || basearr.len() > ruishu::MAX_BASEARR_LEN
        {
            return Err(SessionError::RuishuError {
                msg: format!(
                    "invalid basearr length: expected non-empty multiple of 16 up to {}, got {}",
                    ruishu::MAX_BASEARR_LEN,
                    basearr.len()
                ),
            });
        }
        let mut state = self
            .ruishu_state
            .write()
            .map_err(|_| SessionError::LockError {
                msg: "ruishu_state lock poisoned".to_string(),
            })?;
        state.basearr = Some(Arc::from(basearr));
        Ok(())
    }

    /// 从已有的 Cookie T (`CtLgrmkSWHBZP`) 中反向提取并记住 basearr。
    ///
    /// 应先通过 [`Self::set_ruishu_challenge_from_page`] 记录对应挑战，再注入 Cookie T。
    ///
    /// ```no_run
    /// # use rsmycqu::session::Session;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let session = Session::new();
    /// session.set_basearr_from_cookie("从浏览器复制的 Cookie T")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_basearr_from_cookie(&self, cookie_t: &str) -> Result<(), SessionError> {
        let dec = ruishu::decrypt_cookie_t(cookie_t)?;
        self.set_basearr(&dec.basearr)
    }

    /// 获取当前会话记住的 basearr
    pub fn basearr(&self) -> Option<Arc<[u8]>> {
        self.ruishu_state
            .read()
            .ok()
            .and_then(|state| state.basearr.clone())
    }

    /// 注入站点外层脚本（mainjs）源码，用于无 basearr 时补算。
    ///
    /// 与 [`set_ruishu_challenge_from_page`](Self::set_ruishu_challenge_from_page)
    /// 一起使用时，`Session::execute` 遇到瑞数 `412` 会自动生成 Cookie T 并重试一次。
    ///
    /// ```no_run
    /// # use rsmycqu::session::Session;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let session = Session::new();
    /// let mainjs = std::fs::read_to_string("mainjs.js")?;
    /// session.set_mainjs(&mainjs);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_mainjs(&self, mainjs: &str) {
        if let Ok(mut lock) = self.ruishu_mainjs.write() {
            *lock = Some(mainjs.to_string());
        }
    }

    /// 从页面 HTML 提取并记录 `$_ts.cd` 与 `$_ts.nsd` 挑战。
    ///
    /// 挑战变化时清除旧内层密文；随后由 [`Self::set_mainjs`] 提供的脚本重新生成。
    ///
    /// ```
    /// # use rsmycqu::session::Session;
    /// let session = Session::new();
    /// let page_html = r#"<script>$_ts.cd="challenge";$_ts.nsd=85762</script>"#;
    /// assert!(session.set_ruishu_challenge_from_page(page_html));
    /// ```
    pub fn set_ruishu_challenge_from_page(&self, page_html: &str) -> bool {
        match (extract_ts_cd(page_html), extract_ts_nsd(page_html)) {
            (Some(cd), Some(nsd)) => {
                let Ok(mut state) = self.ruishu_state.write() else {
                    return false;
                };
                if let Some((current_cd, current_nsd)) = &state.challenge {
                    if current_cd == cd && *current_nsd == nsd {
                        return true;
                    }
                    for name in ["CtLgrmkSWHBZP", "CtLgrmkSWHBZT"] {
                        if self.cookie_jar.remove_cqu_cookie(name).is_err() {
                            return false;
                        }
                    }
                    state.basearr = None;
                }
                state.challenge = Some((cd.to_string(), nsd));
                true
            }
            _ => false,
        }
    }
}

impl Session {
    /// 获取是否已经通过[`sso`](crate::sso)登录
    pub fn is_login(&self) -> bool {
        self.is_login
    }

    /// 获取登录信息
    pub fn access_infos(&self) -> &AccessInfos {
        &self.access_infos
    }

    /// 设置登录信息
    pub fn set_access_infos(self, infos: AccessInfos) -> Self {
        Session {
            access_infos: infos,
            ..self
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Session::new()
    }
}

/// 判断响应是否为 CQU 瑞数拦截，需重算 Cookie T 后重发
fn is_ruishu_blocked(url: &reqwest::Url, status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::PRECONDITION_FAILED && is_cqu_host(url)
}

fn is_cqu_host(url: &reqwest::Url) -> bool {
    url.host_str()
        .is_some_and(|h| h == "cqu.edu.cn" || h.ends_with(".cqu.edu.cn"))
}

/// `/api/protected/*` 与 `/linkid/protected/*` 强制校验的 CSRF 头名
pub(crate) const CSRF_KEY_HEADER: header::HeaderName = header::HeaderName::from_static("csrf-key");
/// 见 [`CSRF_KEY_HEADER`]
pub(crate) const CSRF_VALUE_HEADER: header::HeaderName =
    header::HeaderName::from_static("csrf-value");

/// 站点前端为含 `protected` 的请求随机生成 32 位 key，并把
/// `base64(key)` 前后半段拼接后取 MD5 作为校验值
fn csrf_value(key: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use md5::{Digest, Md5};

    let encoded = STANDARD.encode(key);
    let joined = format!(
        "{}{}{}",
        &encoded[..encoded.len() / 2],
        encoded,
        &encoded[encoded.len() / 2..]
    );
    hex::encode(Md5::digest(joined.as_bytes()))
}

/// 生成一组新的 CSRF 头；随机性仅用于保证 key 唯一，不承担安全职责
fn csrf_headers() -> (header::HeaderValue, header::HeaderValue) {
    use std::{
        collections::hash_map::RandomState,
        hash::{BuildHasher, Hasher},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut key = String::with_capacity(32);
    let mut seed = RandomState::new().build_hasher();
    seed.write_u64(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
            ^ COUNTER.fetch_add(1, Ordering::Relaxed).rotate_left(17),
    );
    let mut state = seed.finish();
    while key.len() < 32 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        key.push(ALPHABET[(state >> 33) as usize % ALPHABET.len()] as char);
    }

    let value = csrf_value(&key);
    (
        header::HeaderValue::from_str(&key).expect("csrf key is ASCII alphanumeric"),
        header::HeaderValue::from_str(&value).expect("csrf value is lowercase hex"),
    )
}

fn extract_ts_nsd(html: &str) -> Option<u32> {
    const MARKER: &str = "$_ts.nsd=";
    let start = html.find(MARKER)? + MARKER.len();
    let rest = html[start..].trim_start_matches(['"', '\'']);
    let len = rest.bytes().take_while(u8::is_ascii_digit).count();
    rest[..len].parse().ok()
}

fn extract_ts_cd(html: &str) -> Option<&str> {
    const MARKERS: [&str; 2] = [r#"$_ts.cd=""#, r#"$_ts.cd='"#];
    for marker in MARKERS {
        if let Some(start) = html.find(marker) {
            let rest = &html[start + marker.len()..];
            let quote = if marker.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = rest.find(quote) {
                return Some(&rest[..end]);
            }
        }
    }
    None
}

fn ruishu_cookie_names(url: &reqwest::Url) -> (&'static str, &'static str) {
    if url.host_str() == Some("my.cqu.edu.cn") {
        ("CtLgrmkSWHBZS", "CtLgrmkSWHBZT")
    } else {
        ("CtLgrmkSWHBZO", "CtLgrmkSWHBZP")
    }
}

fn has_cookie_t(header: &header::HeaderValue, cookie_t_name: &str) -> bool {
    header.to_str().is_ok_and(|cookies| {
        cookies.split(';').any(|cookie| {
            cookie
                .trim()
                .split_once('=')
                .is_some_and(|(name, value)| name == cookie_t_name && !value.is_empty())
        })
    })
}
