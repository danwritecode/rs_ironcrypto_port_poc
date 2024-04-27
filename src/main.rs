use std::time::{SystemTime, UNIX_EPOCH};
use base64::{Engine as _, engine::general_purpose};
use anyhow::Result;

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use sha1::Sha1;
use subtle::ConstantTimeEq;


const mac_prefix: &str = "Fe26.2";

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

    if mac_prefix != prefix {
        panic!("Invalid prefix");
    }

    let res = validate_hmac_signature(password, &mac_base_string, hmac_salt, 1, 32, hmac)?;

    println!("res: {}", res);

    Ok(())
}

pub fn validate_hmac_signature(
    password: &str,
    data: &str,
    salt: &str,
    iterations: u32,
    key_length: usize,
    hmac: &str,
) -> Result<bool> {
    let mut derived_key = vec![0u8; key_length];
    pbkdf2::<Hmac<Sha1>>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut derived_key,
    )?;

    let data_buffer = data.as_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(&derived_key)?;
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


fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let bytes = general_purpose::URL_SAFE.decode(input)?;
    Ok(bytes)
}

fn encode_base64(input: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
}


// create test boilerplate here
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let rsMacString = "Fe26.2**8067806aef1cf39ae8ba36952ac3ab8fcc37fbf5fc0a252c878c9df83caab975*26nEjPYnbGntZ9OERoDJcQ*LV5X8PRAWUKwwRH_mjEaMyAlvdTwwW52OuVNeYrSsqKTPQItlJQv3aN1NuWkt7jRctkS5wjiBO2gcS6aJLyzZcQ7W1eB8P5ARV6yW1DHjYGv3umPDiQDOSx3A-SUtG6ulQbDvmV6VuDHUvq8uO2YIxHOIDrRZrGsCHFnVbBgvuTZE8-7RhrjFK50ej4-LlBRNT7Gu4FDcZNu3dzxw9E4hkCvRZW29Npa-KC_rr6EFKmigv_OdzLW6Yddh81ctwLHbmb8a1Xwl7a25nzwik64Ks0H0pvg4R9MN64IiPRj_1ikvjzTT_zz4dbSdh8s8svjK07Pt5RozjY2ySrx-adxbI0nmNXAf7ZNF5EfTiuITU2aXr9Z4VU5cwIZNZhWzIuFyzMo9hyyFdVR2_WsLPlzUVT_HgLSKEulWttfyDsuMvnV5ULx1745P1nXpRf_SAIgxBuqdsncNyUaADLyUh2fU8UswieiuMHykJD3xouMFoxXJ49BWKQaRyHT_lhh2eUAQKAIij278oSR4r76v9NW9w__dwOihmcy12ffY3sZgbXaPHktIdJxBHbFalWgH6PdnUt8fBgP1B8zHdtAr6qu2Vs0GqlwyGo4D1G307ogALfUn0wq0qspYd2zlf44jzKC5QOn-YXkTJL1KJ49W_CpcfNN17mrUjvUG1VscAhMy0VMt5J1pzgOgRwXwhSHH_i-TEDIMDTybdj-pNfcsD-r1GBgz7UhdhHQqsfFDPisUabJG220JIbUvrxPo0hxY8peJ8NjTSfuQBLxY4hwAAQl8g06iU99ifcs-Lfcy7akxHMTCFPi5E155oCK5nJixt3D3zSlxGM6xPBKzkehdWr_zgtiaKqy48VSW0zr_nGcNyQsOS5l63ANvbizfiX2AaRwFRnl1cBHmr1AscRkfRzTHOv1kC3Xb4YhuTU7HfOBQVlS833vv7i-lpjdgr-EpxJUXx1yhNxXSQ76KyoJqIazZYBmsiSvSET3mHV08Mi7MG_6aNzphfoimI8aoCzS-rELwpihscsU_8lfIesWaC52BnNozdXzg-i_C9WYFfTaoLzARWxB1GTHSuhax5zvmb8EOMgBjbfjcRt8iUz0ZZe2Fbu3yDnpqEKBCE2f5yvaVzOS7PSq1UjDO-W9ZirEx0WbJW9tT3HF4tvsftLndcVSvnI1hZlCjOhJfsrmIBkLQtIvXEQFVGu4HMj0dEu7yMChWKtFocRlA2XB2igmV8w68BU0Ng-8pUsDXHeg8PRvOt5Y6NlMHltTn5vInCg8uvNM37tNpvLja3HW7XnbMr-c2xT6ELHQKXf6ivbWzzlIJMcwuSNL9HrB1OaFlqX34IQYkCwQ3bUBpCPoQdarNyyHlcPmSQJfm6V3nmBtA1cc0sGKrY6ayx8FY5iG-1H3A4of2_hp1LbGv8zl44VQKJsE9-VEi1PL9D6kwUjfWW52OKFei7L3C-Wl_2Hzf4xNRJ1mWsi6Lw-yZouH89-ZeGiddndfxFTu9LMFj6lq0UJd2LX7HXy9_txZlPxyInAcOmFakjNtjdRunqZAffv7iRviQhw-o-rnZP7psmHdI-mD_FMy4mRfmfVdYIgVGYpPWWGMIdzGyclQOeh6yyv1W0qjgM2uJNAKyJN2ds_t7ktDlIBrfCCIfgf1wmJbymjvtqRVZSNWTvOAyjsfc98LfiMErU-4dOE-pUm1VgmRCk2-ELfAQSkBwMR_Y53-lJvb7XytwpCQsROJceJDdM2TFEAJVg*";
        let jsMacString = "Fe26.2**8067806aef1cf39ae8ba36952ac3ab8fcc37fbf5fc0a252c878c9df83caab975*26nEjPYnbGntZ9OERoDJcQ*LV5X8PRAWUKwwRH_mjEaMyAlvdTwwW52OuVNeYrSsqKTPQItlJQv3aN1NuWkt7jRctkS5wjiBO2gcS6aJLyzZcQ7W1eB8P5ARV6yW1DHjYGv3umPDiQDOSx3A-SUtG6ulQbDvmV6VuDHUvq8uO2YIxHOIDrRZrGsCHFnVbBgvuTZE8-7RhrjFK50ej4-LlBRNT7Gu4FDcZNu3dzxw9E4hkCvRZW29Npa-KC_rr6EFKmigv_OdzLW6Yddh81ctwLHbmb8a1Xwl7a25nzwik64Ks0H0pvg4R9MN64IiPRj_1ikvjzTT_zz4dbSdh8s8svjK07Pt5RozjY2ySrx-adxbI0nmNXAf7ZNF5EfTiuITU2aXr9Z4VU5cwIZNZhWzIuFyzMo9hyyFdVR2_WsLPlzUVT_HgLSKEulWttfyDsuMvnV5ULx1745P1nXpRf_SAIgxBuqdsncNyUaADLyUh2fU8UswieiuMHykJD3xouMFoxXJ49BWKQaRyHT_lhh2eUAQKAIij278oSR4r76v9NW9w__dwOihmcy12ffY3sZgbXaPHktIdJxBHbFalWgH6PdnUt8fBgP1B8zHdtAr6qu2Vs0GqlwyGo4D1G307ogALfUn0wq0qspYd2zlf44jzKC5QOn-YXkTJL1KJ49W_CpcfNN17mrUjvUG1VscAhMy0VMt5J1pzgOgRwXwhSHH_i-TEDIMDTybdj-pNfcsD-r1GBgz7UhdhHQqsfFDPisUabJG220JIbUvrxPo0hxY8peJ8NjTSfuQBLxY4hwAAQl8g06iU99ifcs-Lfcy7akxHMTCFPi5E155oCK5nJixt3D3zSlxGM6xPBKzkehdWr_zgtiaKqy48VSW0zr_nGcNyQsOS5l63ANvbizfiX2AaRwFRnl1cBHmr1AscRkfRzTHOv1kC3Xb4YhuTU7HfOBQVlS833vv7i-lpjdgr-EpxJUXx1yhNxXSQ76KyoJqIazZYBmsiSvSET3mHV08Mi7MG_6aNzphfoimI8aoCzS-rELwpihscsU_8lfIesWaC52BnNozdXzg-i_C9WYFfTaoLzARWxB1GTHSuhax5zvmb8EOMgBjbfjcRt8iUz0ZZe2Fbu3yDnpqEKBCE2f5yvaVzOS7PSq1UjDO-W9ZirEx0WbJW9tT3HF4tvsftLndcVSvnI1hZlCjOhJfsrmIBkLQtIvXEQFVGu4HMj0dEu7yMChWKtFocRlA2XB2igmV8w68BU0Ng-8pUsDXHeg8PRvOt5Y6NlMHltTn5vInCg8uvNM37tNpvLja3HW7XnbMr-c2xT6ELHQKXf6ivbWzzlIJMcwuSNL9HrB1OaFlqX34IQYkCwQ3bUBpCPoQdarNyyHlcPmSQJfm6V3nmBtA1cc0sGKrY6ayx8FY5iG-1H3A4of2_hp1LbGv8zl44VQKJsE9-VEi1PL9D6kwUjfWW52OKFei7L3C-Wl_2Hzf4xNRJ1mWsi6Lw-yZouH89-ZeGiddndfxFTu9LMFj6lq0UJd2LX7HXy9_txZlPxyInAcOmFakjNtjdRunqZAffv7iRviQhw-o-rnZP7psmHdI-mD_FMy4mRfmfVdYIgVGYpPWWGMIdzGyclQOeh6yyv1W0qjgM2uJNAKyJN2ds_t7ktDlIBrfCCIfgf1wmJbymjvtqRVZSNWTvOAyjsfc98LfiMErU-4dOE-pUm1VgmRCk2-ELfAQSkBwMR_Y53-lJvb7XytwpCQsROJceJDdM2TFEAJVg*";

        assert_eq!(rsMacString, jsMacString);
    }
}

