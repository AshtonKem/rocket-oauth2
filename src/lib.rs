use crate::OAuthError::Unauthenticated;
use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::{Outcome, Request};
use std::collections::HashMap;

pub struct OAuthConfiguration {
    pub client_id: String,
    pub client_secret: String,
    pub extra_scopes: Vec<String>,
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

pub fn get_access_token(config: &OAuthConfiguration, code: String) -> String {
    let resp: HashMap<String, String> = reqwest::get("https://oauth2.googleapis.com/token")
        .query(&[
            ("code", code),
            ("client_id", config.client_id),
            ("client_secret", config.client_secret),
            ("grant_type", "authorization_code"),
            ("redirect_url", "https://example.com/oauth"),
        ])
        .await?
        .json::<HashMap<String, String>>()
        .await?;

    resp.get("access_token")?.to_string()
}
