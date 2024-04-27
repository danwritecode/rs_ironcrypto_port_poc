use std::{str::from_utf8, time::{SystemTime, UNIX_EPOCH}};
use base64::{Engine as _, engine::general_purpose};
use anyhow::Result;

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use sha1::Sha1;
use subtle::ConstantTimeEq;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use serde_json::Value;


type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const MAC_PREFIX: &str = "Fe26.2";

fn main() -> Result<()> {
    let password = "";
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis()).unwrap();

    let token = "".to_string();
    let parts = token.split("*").collect::<Vec<&str>>();

    if parts.len() != 8 {
        panic!("Invalid token");
    }

    let prefix = parts[0];
    let password_id = parts[1];
    let encryption_salt = parts[2];
    let encryption_iv_b64 = parts[3];
    let encrypted_b64 = parts[4];
    let expiration = parts[5];
    let hmac_salt = parts[6];
    let hmac = parts[7];
    let mac_base_string = format!("{}*{}*{}*{}*{}*{}", prefix, password_id, encryption_salt, encryption_iv_b64, encrypted_b64, expiration);

    if MAC_PREFIX != prefix {
        panic!("Invalid prefix");
    }

    // validate the hmac
    let hmac_key = generate_key(password, hmac_salt, 1, 32)?;
    let sig_is_valid = validate_hmac_signature(&mac_base_string, hmac, hmac_key)?;

    // decrypt the data
    let decrypt_key = generate_key(password, encryption_salt, 1, 32)?;
    let encryption_iv = decode_base64(encryption_iv_b64)?;
    let ciphertext = decode_base64(encrypted_b64)?;

    let key_array: [u8; 32] = decrypt_key.try_into().unwrap();
    let iv_array: [u8; 16] = encryption_iv[..].try_into().unwrap();

    let mut buf = vec![0u8; ciphertext.len()];
    buf.copy_from_slice(&ciphertext);

    let pt = Aes256CbcDec::new(&key_array.into(), &iv_array.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&mut buf)
        .unwrap();

    let pt_json: Value = serde_json::from_str(from_utf8(&pt).unwrap())?;

    // profit
    println!("pt_json: {:?}", pt_json);

    Ok(())
}

pub fn validate_hmac_signature(
    data: &str,
    hmac: &str,
    key: Vec<u8>,
) -> Result<bool> {
    let data_buffer = data.as_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
    mac.update(data_buffer);

    let result = mac.finalize();

    let result_bytes = result.into_bytes();
    let result_bytes_b64 = encode_base64(&result_bytes);
    let hmac_bytes = hmac.as_bytes();

    if ConstantTimeEq::ct_eq(result_bytes_b64.as_bytes(), hmac_bytes).into() {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn generate_key(password: &str, salt: &str, iterations: u32, key_length: usize) -> Result<Vec<u8>> {
    let mut derived_key = vec![0u8; key_length];
    pbkdf2::<Hmac<Sha1>>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut derived_key,
    )?;

    Ok(derived_key)
}

fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let bytes = general_purpose::URL_SAFE_NO_PAD.decode(input)?;
    Ok(bytes)
}

fn encode_base64(input: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
}
