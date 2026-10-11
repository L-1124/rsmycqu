use rstest::rstest;

#[cfg(feature = "card")]
use super::card_access_parser;
use super::{SSOLoginPageData, sso_login_parser};

#[rstest]
fn test_login_page_parser() {
    let data = sso_login_parser(include_str!("sso_login_page.html")).unwrap();
    assert_eq!(data, SSOLoginPageData {
        login_croypto: "08L9sDJM3F4=".to_string(),
        captcha_url: "".to_string(),
        captcha_payload: "".to_string(),
        sso_second: "".to_string(),
        phone_number: "".to_string(),
        user_email: "".to_string(),
        current_login_type: "UsernamePassword".to_string(),
        user_object_id: String::new(),
        login_page_flowkey: "471d9bf0-b06e-41ba-88a1-21ee8f0eaf0a_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".to_string(),
    });
}

#[rstest]
fn test_login_page_parser_captcha_required() {
    let html = r#"<html><body>
        <p id="login-croypto">sample_key</p>
        <p id="login-page-flowkey">sample_flowkey</p>
        <p id="captcha-url">api/captcha/generate/DEFAULT</p>
        <input name="captcha_payload" value="V9dEys3Ijdu37MWEEF7CrA==" />
    </body></html>"#;
    let data = sso_login_parser(html).unwrap();
    assert_eq!(
        data.captcha_url,
        "https://sso.cqu.edu.cn/api/captcha/generate/DEFAULT"
    );
    assert_eq!(data.captcha_payload, "V9dEys3Ijdu37MWEEF7CrA==");
}

#[rstest]
fn test_login_page_parser_second_factor() {
    let html = r#"<html><body>
        <p id="login-croypto">sample_key</p>
        <p id="login-page-flowkey">flowkey_sample_2fa_test</p>
        <p id="sso-second">smsLogin</p>
        <p id="phone-number">*******1230</p>
        <p id="user-email-value">te***@cqu.edu.cn</p>
        <p id="user-object-id">user-id</p>
        <p id="current-login-type">UsernamePassword</p>
    </body></html>"#;
    let data = sso_login_parser(html).unwrap();
    assert_eq!(data.sso_second, "smsLogin");
    assert_eq!(data.phone_number, "*******1230");
    assert_eq!(data.user_email, "te***@cqu.edu.cn");
    assert_eq!(data.login_page_flowkey, "flowkey_sample_2fa_test");
    assert_eq!(data.current_login_type, "UsernamePassword");
    assert_eq!(data.user_object_id, "user-id");
}

#[cfg(feature = "card")]
#[rstest]
fn test_card_access_page_parser() {
    let data = card_access_parser(include_str!("card_access_page.html")).unwrap();
    assert_eq!(data, "1fd67d4a48c5b9681280f22899e54bd1")
}
