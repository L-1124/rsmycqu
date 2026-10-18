use reqwest::Url;
use rstest::rstest;

use super::{is_exact_cas_success_callback, validate_login_redirect};

#[rstest]
#[case::same_origin_path("https://sso.cqu.edu.cn/authserver/index.do", true)]
#[case::same_origin_with_query("https://sso.cqu.edu.cn/authserver/index.do?service=test", true)]
#[case::same_origin_explicit_port("https://sso.cqu.edu.cn:443/authserver/index.do", true)]
#[case::exact_cas_success_callback("https://self.cqu.edu.cn/cas-success", true)]
#[case::exact_cas_success_callback_explicit_port("https://self.cqu.edu.cn:443/cas-success", true)]
#[case::cas_callback_with_query("https://self.cqu.edu.cn/cas-success?ticket=ST-123456", false)]
#[case::cas_callback_with_fragment("https://self.cqu.edu.cn/cas-success#token", false)]
#[case::cas_callback_with_trailing_slash("https://self.cqu.edu.cn/cas-success/", false)]
#[case::cas_callback_other_path("https://self.cqu.edu.cn/login", false)]
#[case::cas_callback_root("https://self.cqu.edu.cn/", false)]
#[case::cas_callback_http_downgrade("http://self.cqu.edu.cn/cas-success", false)]
#[case::cas_callback_alt_port("https://self.cqu.edu.cn:8443/cas-success", false)]
#[case::cas_callback_with_user_pass("https://user:pass@self.cqu.edu.cn/cas-success", false)]
#[case::subdomain_spoof_prefix("https://evilsso.cqu.edu.cn/authserver/login", false)]
#[case::subdomain_spoof_suffix("https://sso.cqu.edu.cn.attacker.com/cas-success", false)]
#[case::other_cqu_subdomain("https://my.cqu.edu.cn/cas-success", false)]
#[case::other_cqu_subdomain_news("https://news.cqu.edu.cn/", false)]
#[case::external_domain("https://evil.cqu.com/cas-success", false)]
#[case::same_origin_http_downgrade("http://sso.cqu.edu.cn/authserver/index.do", false)]
#[case::same_origin_alt_port("https://sso.cqu.edu.cn:8443/authserver/index.do", false)]
#[case::same_origin_embedded_credentials(
    "https://user:pass@sso.cqu.edu.cn/authserver/index.do",
    false
)]
fn test_validate_login_redirect_boundaries(#[case] target_str: &str, #[case] should_accept: bool) {
    let base = Url::parse("https://sso.cqu.edu.cn/login").unwrap();
    let target = Url::parse(target_str).unwrap();
    let res = validate_login_redirect(&base, &target);
    assert_eq!(res.is_ok(), should_accept, "target={target_str}");
}

#[rstest]
#[case::exact_target("https://self.cqu.edu.cn/cas-success", true)]
#[case::explicit_port_target("https://self.cqu.edu.cn:443/cas-success", true)]
#[case::with_query("https://self.cqu.edu.cn/cas-success?query=1", false)]
#[case::with_fragment("https://self.cqu.edu.cn/cas-success#frag", false)]
#[case::wrong_path("https://self.cqu.edu.cn/cas-success-fake", false)]
#[case::subdomain("https://fake.self.cqu.edu.cn/cas-success", false)]
#[case::scheme_http("http://self.cqu.edu.cn/cas-success", false)]
fn test_is_exact_cas_success_callback(#[case] target_str: &str, #[case] expected: bool) {
    let target = Url::parse(target_str).unwrap();
    assert_eq!(is_exact_cas_success_callback(&target), expected);
}
