use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::response::Redirect;
use rocket::{Outcome, Request};
use std::collections::HashMap;

pub struct OAuthConfiguration {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
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

pub fn redirect_to_oauth(config: &OAuthConfiguration) -> Redirect {
    Redirect::to(format!("https://accounts.google.com/o/oauth2/v2/auth?scope={}&access_type=offline&include_granted_scopes=true&state=state_parameter_passthrough_value&redirect_uri={}&response_type=code&client_id=${}",
                         "fake-scope", config.redirect_uri, config.client_id))
}

pub async fn get_access_token(config: &OAuthConfiguration, code: String) -> String {
    let resp: HashMap<String, String> = reqwest::Client::new()
        .get("https://oauth2.googleapis.com/token")
        .query(&[
            ("code", code),
            ("client_id", config.client_id.to_string()),
            ("client_secret", config.client_secret.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("redirect_url", "https://example.com/oauth".to_string()),
        ])
        .send()
        .await
        .unwrap()
        .json::<HashMap<String, String>>()
        .await
        .unwrap();

    resp.get("access_token").unwrap().to_string()
}
