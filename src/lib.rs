/*!
 * This is a crate intended for use with Steam's old, outdated OpenID 2.0 implementation.
 *
 * Note: this crate does not add a login redirect endpoint *to* Steam's server (yet, possibly), but simply
 * checks against parameters to see if they are valid.
 *
 * The source is maintained on <https://github.com/prplnorangesoda/steamopenid>.
 *
 * This crate depends on Reqwest (for now) but I'll probably rewrite it to work with cURL.
 */

use derive_more::{Display, Error, From};
use reqwest::redirect::Policy;
use std::collections::HashMap;

#[derive(Debug, Display, From, Error)]
pub enum ApiError {
    ReqwestError(reqwest::Error),
    KeyValuesError(kv::DecodeError),
    Handling,
}

///
/// Send a full OpenID 2.0 spec check_authentication __direct request__ to the Steam servers, using a provided HashMap
/// of openid params.
///
/// The easiest way to create a valid HashMap is to get input from an OpenID Indirect Response
/// (shown in the simple.rs example included with this crate) and run it through `kv::decode_keyvalues`.
pub async fn verify_auth_keyvalues(
    key_values_map: &HashMap<String, String>,
) -> Result<bool, ApiError> {
    let body_string = kv::encode_keyvalues(key_values_map);
    let body_string = body_string.replace("openid.mode=id_res", "openid.mode=check_authentication");

    send_verify_request_raw(body_string).await
}

///
/// Send a full POST request to the steam servers,
/// using the provided body.
///
pub async fn send_verify_request_raw(body: String) -> Result<bool, ApiError> {
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()?;

    println!("{body}");
    let resp = client
        .post("https://steamcommunity.com/openid/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;

    if resp.status() != reqwest::StatusCode::OK {
        println!("{resp:?}");
        return Err(ApiError::Handling);
    };

    let text = resp.text().await?;
    Ok(text.contains("is_valid:true"))
}

pub mod kv {
    /*!
     * Functions to work with OpenID Key-value pairs.
     */
    use derive_more::derive::{Display, Error};
    use std::collections::{HashMap, VecDeque};
    use urlencoding::{decode, encode};

    #[derive(Debug, Display, Error)]
    pub enum DecodeError {
        MalformedInput,
        ConversionError,
    }
    ///
    /// Take an application/x-www-form-urlencoded POST body string of keyvalues and decode it into a HashMap.
    /// Returns ConversionError if there was an error internally, returns MalformedInput if the input created something incorrect.
    /// ## Examples
    /// ```
    /// # use steamopenid::openid_kv::decode_keyvalues;
    /// let kv_decoded = decode_keyvalues(
    ///     concat!(
    ///             "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
    ///             "&openid.op_endpoint=https%3A%2F%2Fsteamcommunity.com%2Fopenid%2Flogin"
    ///     ))
    /// .expect("should be able to parse input string");
    ///
    /// let namespace = kv_decoded.get("openid.ns").expect("value should be created");
    /// let op_endpoint = kv_decoded.get("openid.op_endpoint").expect("value should be created");
    ///
    /// assert!(!kv_decoded.is_empty());
    /// ```
    ///
    pub fn decode_keyvalues(kv: &str) -> Result<HashMap<String, String>, DecodeError> {
        use DecodeError::*;
        let statements = kv.split('&');
        let mut out = HashMap::new();
        for statement in statements {
            // take as a VecDeque to pop_front
            let mut result: VecDeque<&str> = statement.split('=').collect();
            if result.len() != 2 {
                return Err(MalformedInput);
            }
            let key = result.pop_front().ok_or(ConversionError)?.to_owned();
            let value = decode(result.pop_front().ok_or(ConversionError)?)
                .expect("should be able to de-encode value")
                .into_owned();
            out.insert(key, value);
        }

        Ok(out)
    }

    ///
    /// Take a HashMap of Openid KeyValues and encode it into an application/x-www-form-urlencoded string.
    ///
    /// ## Examples:
    pub fn encode_keyvalues(kv_map: &HashMap<String, String>) -> String {
        let mut body_string = String::new();
        for (key, value) in kv_map.iter() {
            body_string.push_str(&format!("{0}={1}&", encode(key), encode(value)))
        }

        // Remove the trailing newline that the above loop generates.
        body_string.pop();
        body_string
    }
}
