use crate::providers::{OauthProvider, TokenMessage};
use reqwest::Error;

pub struct GoogleProvider {}

impl OauthProvider for GoogleProvider {
    fn get_redirect(
        &self,
        redirect_uri: &String,
        original_uri: &String,
        client_id: &String,
        scopes: &Vec<&str>,
    ) -> String {
        let mut total_scopes = vec!["profile"];
        total_scopes.append(&mut scopes.clone());

        format!("https://accounts.google.com/o/oauth2/v2/auth?scope={}&access_type=offline&include_granted_scopes=true&redirect_uri={}&response_type=code&client_id={}&state={}",
                total_scopes.join("%20"), redirect_uri, client_id, original_uri)
    }

    fn get_tokens(
        &self,
        code: &String,
        client_id: &String,
        client_secret: &String,
        redirect_uri: &String,
    ) -> Result<TokenMessage, Error> {
        let response = reqwest::blocking::Client::new()
            .post("https://oauth2.googleapis.com/token")
            .header("Accept", "application/json")
            .form(&[
                ("code", code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("grant_type", &"authorization_code".to_string()),
                ("redirect_uri", redirect_uri),
            ])
            .send();

        response.unwrap().json::<TokenMessage>()
    }
}

#[cfg(test)]
mod tests {
    use crate::providers::{GoogleProvider, OauthProvider};

    #[test]
    fn test_redirect() {
        let provider = GoogleProvider {};
        let scopes: Vec<&str> = vec![];
        let expected = "https://accounts.google.com/o/oauth2/v2/auth?scope=profile&access_type=offline&include_granted_scopes=true&redirect_uri=redirect&response_type=code&client_id=client_id&state=original";
        assert_eq!(
            expected,
            provider.get_redirect(
                &"redirect".to_string(),
                &"original".to_string(),
                &"client_id".to_string(),
                &scopes
            )
        );
    }

    #[test]
    fn test_redirect_with_scopes() {
        let provider = GoogleProvider {};
        let scopes: Vec<&str> = vec!["fake-scope"];
        let expected = "https://accounts.google.com/o/oauth2/v2/auth?scope=profile%20fake-scope&access_type=offline&include_granted_scopes=true&redirect_uri=redirect&response_type=code&client_id=client_id&state=original";
        assert_eq!(
            expected,
            provider.get_redirect(
                &"redirect".to_string(),
                &"original".to_string(),
                &"client_id".to_string(),
                &scopes
            )
        );
    }
}
