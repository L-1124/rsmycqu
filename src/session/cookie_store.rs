//! 内部 CookieStore 实现，替代 reqwest 的不透明 Jar，提供对 Cookie 的枚举、快照导出和恢复功能。

use std::sync::RwLock;

use cookie_store::{Cookie, CookieStore, RawCookie};
use reqwest::Url;
use reqwest::header::HeaderValue;

use crate::errors::session::SessionError;

/// 内部线程安全的 Cookie 存储容器
pub(crate) struct InternalCookieStore {
    inner: RwLock<CookieStore>,
}

impl InternalCookieStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: RwLock::new(CookieStore::default()),
        }
    }

    pub(crate) fn from_store(store: CookieStore) -> Self {
        Self {
            inner: RwLock::new(store),
        }
    }

    /// 向存储区注入单个 Cookie 字符串（如 `name=value; Path=/`）
    pub(crate) fn add_cookie_str(&self, cookie_str: &str, url: &Url) -> Result<(), SessionError> {
        let mut store = self.inner.write().map_err(|_| SessionError::LockError {
            msg: "cookie store write lock poisoned".to_string(),
        })?;
        if let Ok(raw) = RawCookie::parse(cookie_str) {
            let cookies = std::iter::once(raw.into_owned());
            store.store_response_cookies(cookies, url);
        }
        Ok(())
    }

    /// 获取针对指定 URL 的 Cookie 请求头字符串（以 `; ` 分隔）
    pub(crate) fn get_cookie_header(&self, url: &Url) -> Result<Option<String>, SessionError> {
        let store = self.inner.read().map_err(|_| SessionError::LockError {
            msg: "cookie store read lock poisoned".to_string(),
        })?;
        let mut values = store.get_request_values(url);
        let Some((name, value)) = values.next() else {
            return Ok(None);
        };
        let mut header = format!("{name}={value}");
        for (name, value) in values {
            header.push_str("; ");
            header.push_str(name);
            header.push('=');
            header.push_str(value);
        }
        Ok(Some(header))
    }

    /// 获取针对指定 URL 的 Cookie HeaderValue
    pub(crate) fn get_header_value(&self, url: &Url) -> Result<Option<HeaderValue>, SessionError> {
        let s = match self.get_cookie_header(url)? {
            Some(s) => s,
            None => return Ok(None),
        };
        Ok(HeaderValue::from_str(&s).ok())
    }

    /// 导出当前存储中所有未过期的 Cookies（包含 session cookies）
    pub(crate) fn export_unexpired(&self) -> Result<Vec<Cookie<'static>>, SessionError> {
        let store = self.inner.read().map_err(|_| SessionError::LockError {
            msg: "cookie store read lock poisoned".to_string(),
        })?;
        Ok(store.iter_unexpired().cloned().collect())
    }

    /// 当前未过期的 Cookie 数量
    pub(crate) fn unexpired_count(&self) -> Result<usize, SessionError> {
        let store = self.inner.read().map_err(|_| SessionError::LockError {
            msg: "cookie store read lock poisoned".to_string(),
        })?;
        Ok(store.iter_unexpired().count())
    }
}
