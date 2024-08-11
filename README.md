# steamopenid (Steam OpenID 2.0 Support)

This crate extends an API using cURL to:
- verify openid2.0 signatures with steam via HTTP requests

In the future, I'm planning on making this crate support all parts of Steam's OpenID 2.0 support, including:
- the discovery phase
- association creation
- creating an auth url to redirect in order to get required information

The spec used to build this crate, as reference: <https://openid.net/specs/openid-authentication-2_0.html>

NOTE: this crate hardcodes Steam's OpenID2.0 Endpoint (https://steamcommunity.com/openid/login) and therefore will not work if Steam decides to change where their openid endpoint is (unlikely, but could happen).

This crate includes an example (examples/simple.rs) that demonstrates how to use this crate effectively.
