#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

use rocket::http::RawStr;
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
        match request.cookies().get_private("access_token") {
            None => Outcome::Failure((Status::Unauthorized, OAuthError::MissingToken)),
            Some(cookie) => Outcome::Success(OAuthUser {
                access_token: cookie.to_string(),
            }),
        }
    }
}

pub fn redirect_to_oauth(config: &OAuthConfiguration) -> Redirect {
    let mut scopes = vec!["profile"];
    scopes.append(&mut config.extra_scopes.clone());

    Redirect::to(format!("https://accounts.google.com/o/oauth2/v2/auth?scope={}&access_type=offline&include_granted_scopes=true&state=state_parameter_passthrough_value&redirect_uri={}&response_type=code&client_id={}",
                         scopes.join(","), config.redirect_uri, config.client_id))
}

#[derive(Deserialize, Debug)]
pub struct TokenMessage {
    pub access_token: String,
    pub expires_in: i32,
}

pub fn get_access_token(config: &OAuthConfiguration, code: String) -> String {
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

    response
        .unwrap()
        .json::<TokenMessage>()
        .unwrap()
        .access_token
}

#[catch(401)]
pub fn not_authorized(req: &Request) -> Redirect {
    let config = req.guard::<State<OAuthConfiguration>>().unwrap();
    redirect_to_oauth(&config)
}

#[get("/oauth/login?<code>")]
pub fn login(config: State<OAuthConfiguration>, code: &RawStr) -> String {
    let access_token = get_access_token(&config, code.url_decode().unwrap());
    format!("Access token is {}", access_token)
}
