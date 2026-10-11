use scraper::{Html, Selector};

#[cfg(test)]
mod tests;

#[inline]
fn selector(selector: &str) -> Selector {
    Selector::parse(selector).expect("static selector should be valid")
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) struct SSOLoginPageData {
    pub(crate) login_croypto: String,
    pub(crate) login_page_flowkey: String,
    /// 非空表示服务端要求验证码
    pub(crate) captcha_url: String,
    /// 验证码负载，仅要求验证码时存在
    pub(crate) captcha_payload: String,
    /// 二次验证标志，非空表示处于二次验证阶段
    pub(crate) sso_second: String,
    /// 绑定手机号掩码
    pub(crate) phone_number: String,
    /// 绑定邮箱掩码
    pub(crate) user_email: String,
    /// 当前登录类型（如 "UsernamePassword"、"smsLogin"）
    pub(crate) current_login_type: String,
    pub(crate) user_object_id: String,
}

pub(crate) fn sso_login_parser(login_html: impl AsRef<str>) -> Option<SSOLoginPageData> {
    let document = Html::parse_document(login_html.as_ref());

    let captcha_url = document
        .select(&selector("p#captcha-url"))
        .next()
        .map(|el| el.text().collect::<String>().trim().to_owned())
        .filter(|s| !s.is_empty())
        .map(|path| {
            if path.starts_with("http://") || path.starts_with("https://") {
                path
            } else {
                format!(
                    "{}/{}",
                    crate::utils::consts::SSO_ROOT_URL,
                    path.trim_start_matches('/')
                )
            }
        })
        .unwrap_or_default();

    let captcha_payload = if captcha_url.is_empty() {
        String::new()
    } else {
        document
            .select(&selector("input[name=captcha_payload]"))
            .next()
            .and_then(|el| el.value().attr("value"))
            .unwrap_or_default()
            .to_owned()
    };

    let sso_second = document
        .select(&selector("p#sso-second"))
        .next()
        .map(|el| el.text().collect::<String>().trim().to_owned())
        .unwrap_or_default();

    let phone_number = document
        .select(&selector("p#phone-number"))
        .next()
        .map(|el| el.text().collect::<String>().trim().to_owned())
        .unwrap_or_default();

    let user_email = document
        .select(&selector("p#user-email-value"))
        .next()
        .map(|el| el.text().collect::<String>().trim().to_owned())
        .unwrap_or_default();

    let current_login_type = document
        .select(&selector("p#current-login-type"))
        .next()
        .map(|el| el.text().collect::<String>().trim().to_owned())
        .unwrap_or_default();

    Some(SSOLoginPageData {
        login_croypto: document
            .select(&selector("p#login-croypto"))
            .next()
            .map(|el| el.text().collect::<String>())
            .unwrap_or_default(),
        login_page_flowkey: document
            .select(&selector("p#login-page-flowkey"))
            .next()?
            .text()
            .collect(),
        captcha_url,
        captcha_payload,
        sso_second,
        phone_number,
        user_email,
        current_login_type,
        user_object_id: document
            .select(&selector("p#user-object-id"))
            .next()
            .map(|el| el.text().collect::<String>().trim().to_owned())
            .unwrap_or_default(),
    })
}

#[cfg(feature = "card")]
pub(crate) fn card_access_parser(html: impl AsRef<str>) -> Option<String> {
    let document = Html::parse_document(html.as_ref());

    document
        .select(&selector("input#ssoticketid"))
        .next()?
        .value()
        .attr("value")
        .map(ToString::to_string)
}
