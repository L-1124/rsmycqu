//! 在[`reqwest::Client`]的基础上增加了额外的状态以保证库运行正确性

use scraper::{Html, Selector};
use std::sync::{Arc, LazyLock, RwLock};

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

#[derive(Debug, Default, Clone)]
struct RuishuState {
    basearr: Option<Arc<[u8]>>,
    challenge: Option<(String, u32)>,
    mainjs_src: Option<reqwest::Url>,
    active_host: Option<String>,
}

/// 无响应 URL 的旧接口默认使用 SSO 来源。
pub(crate) const RUISHU_MAINJS_ROOT: &str = "https://sso.cqu.edu.cn/";

static SCRIPT_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("static script reqwest client")
});

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
                let should_preempt = {
                    let state = self
                        .ruishu_state
                        .read()
                        .map_err(|_| SessionError::LockError {
                            msg: "ruishu_state read lock poisoned".to_string(),
                        })?;
                    state.challenge.is_some()
                        && state
                            .active_host
                            .as_deref()
                            .is_some_and(|h| Some(h) == request.url().host_str())
                };

                if should_preempt {
                    self.ensure_ruishu_material().await?;
                    self.refresh_ruishu_cookie(request.url())?;
                    cookie_header = self.cookie_jar.get_header_value(request.url())?;
                }
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
            let response_url = response.url().clone();
            for cookie_str in response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
            {
                self.cookie_jar.add_cookie_str(cookie_str, &response_url)?;
            }

            let Some(retry) = retry_request.take() else {
                return Ok(response);
            };
            if !is_ruishu_blocked(&response_url, response.status()) {
                return Ok(response);
            }

            // 412 页面本身就是本次请求主机的瑞数挑战页：采纳其中的挑战后再重算。
            // 挑战是各站点独立的（sso 与 my.cqu 的 cd/nsd 不同），Cookie T 名称
            // 也按 host 区分，因此切换站点时多一次 412 往返即可自愈。
            let body = response.text().await.map_err(|e| SessionError::Build {
                source: e.without_url(),
            })?;
            let cd_opt = extract_ts_cd(&body);
            let nsd_opt = extract_ts_nsd(&body);

            let (cd, nsd) = match (cd_opt, nsd_opt) {
                (Some(cd), Some(nsd)) => (cd.to_string(), nsd),
                (None, None) => {
                    let state = self
                        .ruishu_state
                        .read()
                        .map_err(|_| SessionError::LockError {
                            msg: "ruishu_state read lock poisoned".to_string(),
                        })?;
                    let host_matches = state
                        .active_host
                        .as_deref()
                        .is_some_and(|h| Some(h) == response_url.host_str());
                    match &state.challenge {
                        Some((curr_cd, curr_nsd)) if host_matches => (curr_cd.clone(), *curr_nsd),
                        _ => {
                            return Err(SessionError::RuishuError {
                                msg: "412 response carried no usable challenge".to_string(),
                            });
                        }
                    }
                }
                _ => {
                    return Err(SessionError::RuishuError {
                        msg: "412 response carried no usable challenge".to_string(),
                    });
                }
            };

            let script_url = match extract_mainjs_src(&body) {
                Some(src) => Some(resolve_and_validate_script_url(&response_url, &src)?),
                None => None,
            };

            self.adopt_challenge_for_response(&response_url, &cd, nsd, script_url)?;
            self.ensure_ruishu_material().await?;
            if !self.refresh_ruishu_cookie(&response_url)? {
                return Err(SessionError::RuishuError {
                    msg: "failed to generate Cookie T after 412".to_string(),
                });
            }
            request = retry;
        }
    }

    /// 确保会话具备重算 Cookie T 的材料（`basearr` 或 `mainjs`）。
    ///
    /// 页面挑战存在但两者皆无时，按页面记录的外层脚本地址自动下载一次并缓存，
    /// 供之后纯算复用。脚本请求不携带会话 Cookie。
    async fn ensure_ruishu_material(&self) -> Result<(), SessionError> {
        let (has_challenge, has_basearr, has_cached_mainjs, target_src) = {
            let state = self
                .ruishu_state
                .read()
                .map_err(|_| SessionError::LockError {
                    msg: "ruishu_state read lock poisoned".to_string(),
                })?;
            let has_challenge = state.challenge.is_some();
            let has_basearr = state.basearr.is_some();
            let has_cached_mainjs = self
                .ruishu_mainjs
                .read()
                .map_err(|_| SessionError::LockError {
                    msg: "ruishu_mainjs read lock poisoned".to_string(),
                })?
                .is_some();
            let target_src = state.mainjs_src.clone();
            (has_challenge, has_basearr, has_cached_mainjs, target_src)
        };

        if !has_challenge || has_basearr || has_cached_mainjs {
            return Ok(());
        }

        let script_url = target_src.ok_or_else(|| SessionError::RuishuError {
            msg: "basearr missing and no site mainjs script recorded from page".to_string(),
        })?;

        let response = SCRIPT_CLIENT
            .get(script_url.clone())
            .send()
            .await
            .map_err(|e| SessionError::Build {
                source: e.without_url(),
            })?;
        if !response.status().is_success() {
            return Err(SessionError::RuishuError {
                msg: format!("failed to fetch site mainjs (HTTP {})", response.status()),
            });
        }
        let source = response.text().await.map_err(|e| SessionError::Build {
            source: e.without_url(),
        })?;

        let state = self
            .ruishu_state
            .read()
            .map_err(|_| SessionError::LockError {
                msg: "ruishu_state read lock poisoned".to_string(),
            })?;
        let mut mainjs_guard = self
            .ruishu_mainjs
            .write()
            .map_err(|_| SessionError::LockError {
                msg: "ruishu_mainjs write lock poisoned".to_string(),
            })?;
        if state.mainjs_src.as_ref() == Some(&script_url) {
            *mainjs_guard = Some(source);
        }
        Ok(())
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

    fn adopt_challenge_for_response(
        &self,
        url: &reqwest::Url,
        cd: &str,
        nsd: u32,
        script_url: Option<reqwest::Url>,
    ) -> Result<(), SessionError> {
        let mut state = self
            .ruishu_state
            .write()
            .map_err(|_| SessionError::LockError {
                msg: "ruishu_state write lock poisoned".to_string(),
            })?;
        let target_host = url.host_str().unwrap_or("sso.cqu.edu.cn");
        let is_host_change = state
            .active_host
            .as_deref()
            .is_some_and(|h| h != target_host);
        let is_challenge_change = match &state.challenge {
            Some((current_cd, current_nsd)) => current_cd != cd || *current_nsd != nsd,
            None => false,
        };
        let is_source_change = match (&state.mainjs_src, &script_url) {
            (Some(curr), Some(new)) => curr != new,
            _ => false,
        };

        if is_challenge_change || is_source_change || is_host_change {
            if state.challenge.is_some() {
                for name in ["CtLgrmkSWHBZP", "CtLgrmkSWHBZT"] {
                    self.cookie_jar.remove_cqu_cookie(name)?;
                }
                state.basearr = None;
            }
            if is_source_change || is_host_change {
                state.basearr = None;
                let mut mainjs =
                    self.ruishu_mainjs
                        .write()
                        .map_err(|_| SessionError::LockError {
                            msg: "ruishu_mainjs write lock poisoned".to_string(),
                        })?;
                *mainjs = None;
            }
        }

        state.challenge = Some((cd.to_string(), nsd));
        if let Some(src) = script_url {
            state.mainjs_src = Some(src);
        } else if is_host_change {
            state.mainjs_src = None;
        }
        state.active_host = Some(target_host.to_string());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn mainjs_src(&self) -> Option<reqwest::Url> {
        self.ruishu_state
            .read()
            .ok()
            .and_then(|state| state.mainjs_src.clone())
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
    /// 挑战变化时清除旧内层密文；页面中的外层脚本地址也会被记录，
    /// 之后缺少 `basearr` 时由 [`Self::execute`] 按需拉取并纯算。
    ///
    /// ```
    /// # use rsmycqu::session::Session;
    /// let session = Session::new();
    /// let page_html = r#"<script>$_ts.cd="challenge";$_ts.nsd=85762</script>"#;
    /// assert!(session.set_ruishu_challenge_from_page(page_html));
    /// ```
    pub fn set_ruishu_challenge_from_page(&self, page_html: &str) -> bool {
        let extracted_src = extract_mainjs_src(page_html);
        let resolved_src = match extracted_src {
            Some(src) => {
                let Ok(sso_base) = reqwest::Url::parse(RUISHU_MAINJS_ROOT) else {
                    return false;
                };
                match resolve_and_validate_script_url(&sso_base, &src) {
                    Ok(url) => Some(url),
                    Err(_) => return false,
                }
            }
            None => None,
        };

        match (extract_ts_cd(page_html), extract_ts_nsd(page_html)) {
            (Some(cd), Some(nsd)) => {
                let Ok(mut state) = self.ruishu_state.write() else {
                    return false;
                };
                let target_host = "sso.cqu.edu.cn";
                let is_host_change = state
                    .active_host
                    .as_deref()
                    .is_some_and(|h| h != target_host);
                let is_challenge_change = match &state.challenge {
                    Some((current_cd, current_nsd)) => current_cd != cd || *current_nsd != nsd,
                    None => false,
                };
                let is_source_change = match (&state.mainjs_src, &resolved_src) {
                    (Some(curr), Some(new)) => curr != new,
                    _ => false,
                };

                if is_challenge_change || is_source_change || is_host_change {
                    if state.challenge.is_some() {
                        for name in ["CtLgrmkSWHBZP", "CtLgrmkSWHBZT"] {
                            if self.cookie_jar.remove_cqu_cookie(name).is_err() {
                                return false;
                            }
                        }
                        state.basearr = None;
                    }
                    if is_source_change || is_host_change {
                        state.basearr = None;
                        if let Ok(mut mainjs) = self.ruishu_mainjs.write() {
                            *mainjs = None;
                        }
                    }
                }

                state.challenge = Some((cd.to_string(), nsd));
                if let Some(src) = resolved_src {
                    state.mainjs_src = Some(src);
                } else if is_host_change {
                    state.mainjs_src = None;
                }
                state.active_host = Some(target_host.to_string());
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

static RUISHU_SCRIPT_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(r#"script[r="m"][src]"#).expect("valid ruishu script selector")
});

/// 从页面 HTML 提取站点外层脚本（`mainjs`）的 `src`。
///
/// 瑞数加载器以 `r='m'` 且具有 `src` 属性标注该脚本。
pub(crate) fn extract_mainjs_src(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    for element in document.select(&RUISHU_SCRIPT_SELECTOR) {
        if let Some(src) = element.value().attr("src") {
            let trimmed = src.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub(crate) fn validate_script_url(url: &reqwest::Url) -> Result<(), SessionError> {
    if url.scheme() != "https" {
        return Err(SessionError::RuishuError {
            msg: "insecure script scheme; only HTTPS is permitted".to_string(),
        });
    }
    match url.host_str() {
        Some("sso.cqu.edu.cn" | "my.cqu.edu.cn") => {}
        _ => {
            return Err(SessionError::RuishuError {
                msg: "untrusted script host; only sso.cqu.edu.cn and my.cqu.edu.cn are permitted"
                    .to_string(),
            });
        }
    }
    if url.port_or_known_default() != Some(443) {
        return Err(SessionError::RuishuError {
            msg: "non-standard script port".to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SessionError::RuishuError {
            msg: "script URL must not contain user credentials".to_string(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(SessionError::RuishuError {
            msg: "script URL must not contain query or fragment".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn resolve_and_validate_script_url(
    base_url: &reqwest::Url,
    src: &str,
) -> Result<reqwest::Url, SessionError> {
    let joined = base_url.join(src).map_err(|_| SessionError::RuishuError {
        msg: "invalid script URL syntax".to_string(),
    })?;
    validate_script_url(&joined)?;
    if joined.origin() != base_url.origin() {
        return Err(SessionError::RuishuError {
            msg: "script URL must match the challenge response origin".to_string(),
        });
    }
    Ok(joined)
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
