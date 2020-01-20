use crate::OAuthError::Unauthenticated;
use rocket::http::Status;
use rocket::request::FromRequest;
use rocket::{Outcome, Request};

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
    Unauthenticated,
}

impl<'a, 'r> FromRequest<'a, 'r> for OAuthUser {
    type Error = OAuthError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, (Status, Self::Error), ()> {
        match request.cookies().get_private("access_token") {
            None => Outcome::Failure((Status::Unauthorized, Unauthenticated)),
            Some(cookie) => Outcome::Success(OAuthUser {
                access_token: cookie.to_string(),
            }),
        }
    }
}
