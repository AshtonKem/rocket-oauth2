# Rocket Oauth2

This crate is designed to make it easier to integrate Rocket web applications with OAuth2. 

## Disclaimer

This software is *very* rough, arguably in a pre-alpha state. Use at your own caution.

## Prerequisites

`rocket-oauth2` requires both `rocket` (duh), and rocket's private key storage system. This private key system is used to encrypt sensitive tokens in the end-users cookies. The default behavior of Rocket is to auto-generate the encryption key during startup unless if it's hard coded. This behavior will result in strange behavior, as each server will be unable to read the cookies of another, causing all kinds of chaos.

I have not tested this crate with multiple versions of Rocket, so I am uncertain how cross compatible it will be with older versions.

## Use

A full example of this crate is located in `example`, for your reference.

This crate is configured using the `OAuthConfiguration` struct, which is stored in Rocket's built in state mechanism. It's highly recommended that you load all OAuth credentials from `dotenv` or similar crates, to avoid hard coding credentials in source files.

```rust
rocket::ignite()
        .manage(OAuthConfiguration {
            client_id: dotenv::var("CLIENT_ID").unwrap(),
            client_secret: dotenv::var("CLIENT_SECRET").unwrap(),
            extra_scopes: vec![],
            redirect_uri: "http://localhost:8000/oauth/login".to_string(),
        })
```

Out of the box, `rocket-oauth2` provides a number of structs, handlers, and catchers to reduce the boiler plate necessary to support oauth2. These are configured with Rocket using the `mount` and `register` methods.

```rust
rocket::ignite()
  .mount("/",
     routes![rocket_oauth2::login, rocket_oauth2::logout])
  .register(catchers![rocket_oauth2::not_authorized]);
```

This snippet will add two routes to your application, and a single catcher. The routes are `/oauth/login` and `/oauth/logout`. The former is the callback URL used to enable OAuth2 login, and the latter will remove all session state keeping a user logged in.

The `catcher` will automatically catch any HTTP 401 responses within Rocket, and trigger an automatic redirect to the appropriate OAuth2 endpoint. If you don't wish to use this functionality, use the `redirect_to_oauth` function manually to begin the OAuth2 authentication flow.

Endpoints can be restricted using the `OAuthUser` guard. This guard will both provide access to the end-users access_token, as well as automatically enforce OAuth login if the `catch` method above is set.

```rust
#[get("/secret")]
fn secret(_user: OAuthUser) -> &'static str {
    "Secret"
}
```

# Expansion Plans

This crate is ... very incomplete. Here is an incomplete list of things I would like to see done to this crate.

1. Tests
2. Multiple OAuth providers, with pluggable strategies
3. Pluggable session storage strategies
4. Automatic refreshing of access_token, when appropriate
5. Callbacks after successful sign-up event
