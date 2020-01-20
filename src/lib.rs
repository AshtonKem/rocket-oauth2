#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

use rocket::http::Cookie;
use rocket::http::Cookies;
use rocket::http::RawStr;
use rocket::http::SameSite;
use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::response::Redirect;
use rocket::{Outcome, Request, State};
use serde::Deserialize;

pub struct OAuthConfiguration<'a> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub extra_scopes: Vec<&'a str>,
}

pub struct OAuthUser {
    pub access_token: String,
}

#[derive(Debug)]
pub enum OAuthError {
    MissingToken,
}

impl<'a, 'r> FromRequest<'a, 'r> for OAuthUser {
    type Error = OAuthError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, (Status, Self::Error), ()> {
        dbg!(request.cookies().get_private("access_token"));
        match request.cookies().get_private("access_token") {
            None => Outcome::Failure((Status::Unauthorized, OAuthError::MissingToken)),
            Some(cookie) => Outcome::Success(OAuthUser {
                access_token: cookie.to_string(),
            }),
        }
    }
}

pub fn redirect_to_oauth(req: &Request, config: &OAuthConfiguration) -> Redirect {
    let mut scopes = vec!["profile"];
    scopes.append(&mut config.extra_scopes.clone());

    Redirect::temporary(format!("https://accounts.google.com/o/oauth2/v2/auth?scope={}&access_type=offline&include_granted_scopes=true&redirect_uri={}&response_type=code&client_id={}&state={}",
                                scopes.join("%20"), config.redirect_uri, config.client_id, req.uri()))
}

#[derive(Deserialize, Debug)]
struct TokenMessage {
    access_token: String,
    expires_in: i32,
    refresh_token: Option<String>,
}

fn get_access_token(config: &OAuthConfiguration, code: String) -> TokenMessage {
    let response = reqwest::blocking::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .header("Accept", "application/json")
        .form(&[
            ("code", code),
            ("client_id", config.client_id.to_string()),
            ("client_secret", config.client_secret.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("redirect_uri", config.redirect_uri.to_string()),
        ])
        .send();

    let body = response.unwrap().json::<TokenMessage>().unwrap();

    body
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
    let token_message = get_access_token(&config, code.url_decode().unwrap());
    let mut access_cookie = Cookie::new("access_token", token_message.access_token);
    access_cookie.set_same_site(SameSite::Lax);
    cookies.add_private(access_cookie);
    if token_message.refresh_token.is_some() {
        cookies.add_private(Cookie::new(
            "refresh_token",
            token_message.refresh_token.unwrap(),
        ));
    }
    Redirect::temporary("http://localhost:8000/secret")
}

#[get("/oauth/logout")]
pub fn logout(mut cookies: Cookies) -> Redirect {
    cookies.remove_private(Cookie::named("access_token"));
    Redirect::temporary("/")
}
