#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;
extern crate rocket_oauth2;

use rocket::http::Cookie;
use rocket::http::Status;
use rocket::local::Client;
use rocket::Rocket;

use rocket_oauth2::providers::GoogleProvider;
use rocket_oauth2::{OAuthConfiguration, OAuthUser};

#[get("/access_token")]
fn secret(user: OAuthUser) -> String {
    format!("Access Token: {}", user.access_token)
}

#[get("/access_token", rank = 2)]
fn secret_no_auth() -> &'static str {
    panic!("This code should not have executed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_unauthenticated() {
        let client = Client::new(main()).expect("Valid rocket instance");
        let response = client.get("/access_token").dispatch();
        assert_eq!(response.status(), Status::TemporaryRedirect);
        assert_eq!(response.headers().get("Location").last().unwrap(),
                   "https://accounts.google.com/o/oauth2/v2/auth?scope=profile&access_type=offline&include_granted_scopes=true&redirect_uri=http://localhost:8000/oauth/login&response_type=code&client_id=client-id&state=/access_token");
    }

    #[test]
    fn test_secret_authenticated() {
        let client = Client::new(main()).expect("Valid rocket instance");
        let mut response = client
            .get("/access_token")
            .private_cookie(Cookie::new("access_token", "fake-token"))
            .dispatch();
        assert_eq!((&response).status(), Status::Ok);
        assert_eq!(response.body_string().unwrap(), "Access Token: fake-token");
    }
}

fn main() -> Rocket {
    rocket::ignite()
        .manage(OAuthConfiguration::new(
            "client-id".to_string(),
            "client-secret".to_string(),
            "http://localhost:8000/oauth/login",
            vec![],
            GoogleProvider {},
        ))
        .mount(
            "/",
            routes![
                secret,
                secret_no_auth,
                rocket_oauth2::login,
                rocket_oauth2::logout
            ],
        )
        .register(catchers![rocket_oauth2::not_authorized])
}
