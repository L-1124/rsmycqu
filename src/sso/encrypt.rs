use snafu::ResultExt;
use std::sync::LazyLock;

use crate::errors::sso::SSOError;
use rsa::{
    Pkcs1v15Encrypt, RsaPublicKey,
    pkcs8::DecodePublicKey,
    rand_core::{OsRng, RngCore},
};

use crate::{
    errors::sso::{PasswordEncryptSnafu, SSOResult},
    utils::encrypt::*,
};

pub(super) fn encrypt_password(
    page_crypto: impl AsRef<str>,
    password: impl AsRef<str>,
) -> SSOResult<String> {
    let crypto = BASE64PURPOSE
        .decode(page_crypto.as_ref())
        .context(PasswordEncryptSnafu {})?;
    let mut crypto_block = [0xff; 16];
    crypto_block[..crypto.len()].copy_from_slice(&crypto);
    let mut pad_password = pad16(password.as_ref().as_bytes());

    let mut des_enc = Aes128EcbEnc::new_from_slice(&crypto_block).unwrap();
    des_enc.encrypt_blocks(&mut pad_password);

    Ok(
        BASE64PURPOSE.encode(pad_password.iter().fold(Vec::new(), |mut result, x| {
            result.append(&mut x.to_vec());
            result
        })),
    )
}

const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjVr1zKwohU3xA0afprWL
SQvIymaSH/V27MedFc+CecXSnORIFMAp4uEIb4taDq/2X4eMeTI66Mu/rB5GKSFD
bExF2Gu4NaO/CNDpf1gHMScUrIFCh4CDqzBnx17kclvezLkIK0T8FVa4cRsINvzj
bnA6jUSMaf6Fm1n9wTAtW6QYBjssGOEtCj+c38PTBdFMmJbXp3brt1tEBesz6lb3
Fjp76FGvDZ08xtYG8fxYPuiMwKU04eS+mcX/BunwgpU3zwekHYB+PWRIvq0lBry9
Wms25sJE5T/RAv5fEuMLbBkfcZK3+7ivSZthTmPpr2Ap/ji70ZZ6u2jvR5VJq+LJ
HQIDAQAB
-----END PUBLIC KEY-----";

pub(super) struct BindingCipher {
    key: [u8; 16],
}

impl BindingCipher {
    pub(super) fn new() -> SSOResult<(Self, String)> {
        static KEY: LazyLock<Result<RsaPublicKey, String>> = LazyLock::new(|| {
            RsaPublicKey::from_public_key_pem(PUBLIC_KEY).map_err(|err| err.to_string())
        });
        let public_key = KEY.as_ref().map_err(crypto_error)?;
        let mut key = [0; 16];
        OsRng.try_fill_bytes(&mut key).map_err(crypto_error)?;
        let encrypted_key = public_key
            .encrypt(
                &mut OsRng,
                Pkcs1v15Encrypt,
                BASE64PURPOSE.encode(key).as_bytes(),
            )
            .map_err(crypto_error)?;
        Ok((Self { key }, BASE64PURPOSE.encode(encrypted_key)))
    }

    pub(super) fn encrypt(&self, body: &[u8]) -> String {
        let padding = 16 - body.len() % 16;
        let mut bytes = Vec::with_capacity(body.len() + padding);
        bytes.extend_from_slice(body);
        bytes.resize(body.len() + padding, padding as u8);
        let cipher = aes::Aes128::new((&self.key).into());
        for chunk in bytes.as_chunks_mut::<16>().0 {
            let mut block = (*chunk).into();
            cipher.encrypt_block(&mut block);
            *chunk = block.into();
        }
        BASE64PURPOSE.encode(bytes)
    }

    pub(super) fn decrypt(&self, body: &str) -> SSOResult<String> {
        let mut bytes = BASE64PURPOSE.decode(body.trim()).map_err(crypto_error)?;
        if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
            return Err(crypto_error("invalid encrypted response length").into());
        }
        let cipher = aes::Aes128::new((&self.key).into());
        for chunk in bytes.as_chunks_mut::<16>().0 {
            let mut block = (*chunk).into();
            cipher.decrypt_block(&mut block);
            *chunk = block.into();
        }
        let padding = usize::from(bytes[bytes.len() - 1]);
        if !(1..=16).contains(&padding)
            || !bytes[bytes.len() - padding..]
                .iter()
                .all(|&byte| usize::from(byte) == padding)
        {
            return Err(crypto_error("invalid encrypted response padding").into());
        }
        bytes.truncate(bytes.len() - padding);
        String::from_utf8(bytes).map_err(|err| crypto_error(err).into())
    }
}

fn crypto_error(err: impl std::fmt::Display) -> SSOError {
    SSOError::SecondFactorError {
        msg: format!("Binding lookup encryption error: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_cipher_matches_independent_aes_vector_and_rejects_bad_padding() {
        let cipher = BindingCipher {
            key: std::array::from_fn(|i| i as u8),
        };
        let body = r#"{"code":200,"data":{"tel":"phone-token"}}"#;
        let encrypted = "o1w4jhrXbxrE/ATFuYZGdzvFSgAQMp6A/UvBpIrhx4ZtaW3LmZRHK8AqENZfFFmB";
        assert_eq!(cipher.encrypt(body.as_bytes()), encrypted);
        assert_eq!(cipher.decrypt(encrypted).unwrap(), body);
        for malformed in ["", "not base64", "AA==", "xqE7N4ePW4JvT4FiocjYeQ=="] {
            assert!(cipher.decrypt(malformed).is_err(), "{malformed}");
        }
    }
}
