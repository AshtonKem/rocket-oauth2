use reqwest::Error;
use serde::Deserialize;

mod google;

pub use google::GoogleProvider;

#[derive(Deserialize, Debug)]
pub struct TokenMessage {
    pub access_token: String,
    pub expires_in: i32,
    pub refresh_token: Option<String>,
}

pub trait OauthProvider: Send + Sync {
    fn get_redirect(
        &self,
        redirect_uri: &String,
        original_uri: &String,
        client_id: &String,
        scopes: &Vec<&str>,
    ) -> String;

    fn get_tokens(
        &self,
        code: &String,
        client_id: &String,
        client_secret: &String,
        redirect_uri: &String,
    ) -> Result<TokenMessage, Error>;
}
