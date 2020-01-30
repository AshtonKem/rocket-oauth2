#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

#[cfg(test)]
extern crate mockito;

use crate::providers::OauthProvider;
use rocket::http::Cookie;
use rocket::http::Cookies;
use rocket::http::RawStr;
use rocket::http::SameSite;
use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::response::Redirect;
use rocket::{Outcome, Request, State};
use serde::Deserialize;

pub mod providers;

pub struct OAuthConfiguration<'a> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub extra_scopes: Vec<&'a str>,
    provider: Box<dyn OauthProvider>,
}

impl<'a> OAuthConfiguration<'a> {
    pub fn new(
        // These are strings because they're highly likely to come from dotenv
        client_id: String,
        client_secret: String,
        redirect_uri: &str,
        extra_scopes: std::vec::Vec<&'a str>,
        provider: impl OauthProvider + 'static,
    ) -> OAuthConfiguration<'a> {
        OAuthConfiguration {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect_uri: redirect_uri.to_string(),
            extra_scopes,
            provider: Box::new(provider),
        }
    }
}

#[derive(Debug)]
pub struct OAuthUser {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug)]
pub enum OAuthError {
    MissingToken,
}

impl<'a, 'r> FromRequest<'a, 'r> for OAuthUser {
    type Error = OAuthError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, (Status, Self::Error), ()> {
        let refresh_token = request
            .cookies()
            .get_private("refresh_token")
            .map(|cookie| cookie.value().to_string());
        match request.cookies().get_private("access_token") {
            None => Outcome::Failure((Status::Unauthorized, OAuthError::MissingToken)),
            Some(cookie) => Outcome::Success(OAuthUser {
                access_token: cookie.value().to_string(),
                refresh_token,
            }),
        }
    }
}

pub fn redirect_to_oauth(req: &Request, config: &OAuthConfiguration) -> Redirect {
    let url = config.provider.get_redirect(
        &config.redirect_uri,
        &req.uri().to_string(),
        &config.client_id,
        &config.extra_scopes,
    );

    Redirect::temporary(url)
}

#[derive(Deserialize, Debug)]
struct TokenMessage {
    access_token: String,
    expires_in: i32,
    refresh_token: Option<String>,
}

#[catch(401)]
pub fn not_authorized(req: &Request) -> Redirect {
    let config = req.guard::<State<OAuthConfiguration>>().unwrap();
    redirect_to_oauth(req, &config)
}

#[get("/oauth/login?<code>&<state>")]
pub fn login(
    mut cookies: Cookies,
    config: State<OAuthConfiguration>,
    code: &RawStr,
    state: &RawStr,
) -> Redirect {
    let token_message = config
        .provider
        .get_tokens(
            &code.to_string(),
            &config.client_id,
            &config.client_secret,
            &config.redirect_uri,
        )
        .unwrap();
    let mut access_cookie = Cookie::new("access_token", token_message.access_token);
    access_cookie.set_same_site(SameSite::Lax);
    cookies.add_private(access_cookie);
    if token_message.refresh_token.is_some() {
        let mut refresh_cookie = Cookie::new("refresh_token", token_message.refresh_token.unwrap());
        refresh_cookie.set_same_site(SameSite::Lax);
        cookies.add_private(refresh_cookie);
    }
    Redirect::temporary(state.url_decode().unwrap())
}

#[get("/oauth/logout")]
pub fn logout(mut cookies: Cookies) -> Redirect {
    cookies.remove_private(Cookie::named("access_token"));
    cookies.remove_private(Cookie::named("refresh_token"));
    Redirect::temporary("/")
}
