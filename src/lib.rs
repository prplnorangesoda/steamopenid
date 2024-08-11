/*!
 * This is a crate intended for use with Steam's old, outdated OpenID 2.0 implementation.
 *
 * Note: this crate does not add a login redirect endpoint *to* Steam's server (yet, possibly), but simply
 * checks against parameters to see if they are valid.
 *
 * The source is maintained on <https://github.com/prplnorangesoda/steamopenid>.
 *
 * This crate depends on cURL.
 */

use curl::easy;
use derive_more::{Display, Error, From};
use std::collections::HashMap;

#[derive(Debug, Display, From, Error)]
pub enum ApiError {
    KeyValuesError(kv::DecodeError),
    Handling,
}

///
/// Send a full OpenID 2.0 spec check_authentication __direct request__ to the Steam servers, using a provided HashMap
/// of openid params.
///
/// The easiest way to create a valid HashMap is to get input from an OpenID Indirect Response
/// (shown in the simple.rs example included with this crate) and run it through `kv::decode_keyvalues`.
///
/// # Examples
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// # use steamopenid::verify_auth_keyvalues;
/// // Imagine we receive a query at /landing.
/// // We can transform this query into usable data via kv::decode_keyvalues.
/// use steamopenid::kv;
///
/// // Let's use some example parameters here.
/// // This uses a real OpenID Parameter set that was returned by logging in through steam.
/// // Since these were already sent to Steam's API in the past, Steam will
/// // always return `false` to prevent replay attacks.
/// let example_input = "http://example.com/landing?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=id_res&openid.op_endpoint=https%3A%2F%2Fsteamcommunity.com%2Fopenid%2Flogin&openid.claimed_id=https%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F76561198025040446&openid.identity=https%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F76561198025040446&openid.return_to=http%3A%2F%2F127.0.0.1%3A9001%2Flanding&openid.response_nonce=2024-08-11T21%3A00%3A54Z2dkBuPKpVOWpwvuDvFUa1tMqtNg%3D&openid.assoc_handle=1234567890&openid.signed=signed%2Cop_endpoint%2Cclaimed_id%2Cidentity%2Creturn_to%2Cresponse_nonce%2Cassoc_handle&openid.sig=q1PsOzZ%2BgU%2BnpiwLhRi0OYQbzKY%3D";
///
/// let example_input = example_input.replace("http://example.com/landing", "");
/// assert!(example_input.starts_with('?'));
///
/// // Now decode the values into a HashMap via kv::decode_keyvalues:
/// let params = kv::decode_keyvalues(&example_input).expect("should be able to decode value");
///
/// // Now, verify it by calling this function:
/// let result = verify_auth_keyvalues(&params).await;
/// let is_valid = result.expect("API call should have succeeded");
/// // Since this is a dummy example, Steam's API should always return false.
/// assert!(is_valid == false);
/// # }
/// ```
pub async fn verify_auth_keyvalues(
    key_values_map: &HashMap<String, String>,
) -> Result<bool, ApiError> {
    let body_string = kv::encode_keyvalues(key_values_map);
    let body_string = body_string.replace("openid.mode=id_res", "openid.mode=check_authentication");

    send_verify_request_raw(body_string).await
}

struct Collector(Vec<u8>);

impl easy::Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, easy::WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}
///
/// Send a full POST request to the steam servers,
/// using the provided body.
///
async fn send_verify_request_raw(body: String) -> Result<bool, ApiError> {
    // let client = reqwest::Client::builder()
    //     .redirect(Policy::none())
    //     .build()?;
    let mut client = easy::Easy2::new(Collector(Vec::new()));
    client.post(true).unwrap();
    client.post_fields_copy(&body.as_bytes()).unwrap();
    client
        .url("https://steamcommunity.com/openid/login")
        .expect("should be able to set URL");

    client
        .perform()
        .expect("Should end up with a result from steam");

    let status = client.response_code().unwrap();
    // fucked up one liner: extracts the utf8 bytes within the Vec<> inside the Collector
    let resp = String::from_utf8_lossy(&(client.get_ref()).0);
    println!("{body}");
    // let resp = client
    //     .post("https://steamcommunity.com/openid/login")
    //     .header("Content-Type", "application/x-www-form-urlencoded")
    //     .body(body)
    //     .send()
    //     .await?;

    if status != 200
    /* OK */
    {
        println!("{status}");
        return Err(ApiError::Handling);
    };

    Ok(resp.contains("is_valid:true"))
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
    /// # Examples
    /// ```
    /// # use steamopenid::kv::decode_keyvalues;
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
        let cleaned_input = kv.trim().replace("?", "");
        let statements = cleaned_input.split('&');
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
    /// Take a HashMap of KeyValues and encode it into an application/x-www-form-urlencoded string.
    ///
    /// # Examples:
    /// ```
    /// # use steamopenid::kv::encode_keyvalues;
    /// use std::collections::HashMap;
    ///
    /// let mut map: HashMap<String, String> = HashMap::new();
    /// map.insert("openid.example".to_string(), "example".to_string());
    ///
    /// let encoded = encode_keyvalues(&map);
    ///
    /// assert_eq!(encoded, "openid.example=example");
    /// ```
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
