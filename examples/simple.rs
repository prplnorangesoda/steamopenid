/*!
 *  This example creates an HTTP Server according to the Rust Book and
 *  uses the crate to generate useful values from the Steam API.
*/
use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};

static ADDRESS: &'static str = "127.0.0.1";
static PORT: &'static str = "9001";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = format!("{ADDRESS}:{PORT}");
    let server = TcpListener::bind(addr).unwrap();
    println!(
        "Visit http://{ADDRESS}:{PORT}/ in your browser and sign in through Steam, then check the console OR web return."
    );
    println!("This example requires an Internet connection.");

    for stream in server.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream).await;
    }
}

async fn handle_connection(mut stream: TcpStream) {
    let bufreader = BufReader::new(&mut stream);

    let http_req: Vec<_> = bufreader
        .lines()
        .map(|result| result.unwrap())
        .take_while(|line| !line.is_empty())
        .collect();

    let response;
    let get_req = http_req.get(0).unwrap();
    if get_req == "GET / HTTP/1.1" {
        let auth_url = get_auth_url();
        response = format!("HTTP/1.1 302 Found\r\nLocation:{auth_url}\r\n\r\n");
    } else if get_req.starts_with("GET /landing?") {
        handle_landing_request(stream, get_req).await;
        return;
    } else {
        response = String::from("HTTP/1.1 404 Not Found\r\n\r\n");
    }

    stream.write_all(response.as_bytes()).unwrap();
}

async fn handle_landing_request(mut stream: TcpStream, get_line: &str) {
    // Setup line to be fed into decoder
    let get_line = get_line
        .replace("GET /landing?", "")
        .replace(" HTTP/1.1", "");

    println!("Decoding from: {get_line}");

    let map = match steamopenid::kv::decode_keyvalues(&get_line) {
        Ok(o) => o,
        Err(_) => {
            error_return(stream);
            return;
        }
    };

    let is_valid = steamopenid::verify_auth_keyvalues(&map)
        .await
        .expect("should be able to check if signature is valid");

    let resp = format!("Decoded HashMap: {map:#?}\nIs_Valid response from Steam API: {is_valid}\n\nTry coming to this page with different or malformed values after the ?.");

    let len = resp.len();
    stream
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nContent-Type: text/plain\r\n\r\n{resp}").as_bytes())
        .unwrap();
}

pub fn error_return(mut stream: TcpStream) {
    stream
        .write_all("HTTP/1.1 400 Bad Request\r\n\r\n".as_bytes())
        .expect("should be able to write error");
}

pub fn get_auth_url() -> String {
    // let redirect_url = format!(
    //     concat!("https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%",
    //             "2Fidentifier_select&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select",
    //             "&openid.return_to=http%3A%2F%{0}%3A{1}%2Flogin%2Flanding",
    //             "&openid.realm=http%3A%2F%2F127.0.0.1:{2}",
    //             "&openid.mode=checkid_setup",
    //             "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"),
    //     ADDRESS,
    //     PORT,
    //     PORT
    // );

    let redirect_url = String::from("https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.return_to=http%3A%2F%2F127.0.0.1%3A9001%2Flanding&openid.realm=http%3A%2F%2F127.0.0.1:9001%2F&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");

    println!("Created redirect url: {redirect_url}");
    redirect_url
}
