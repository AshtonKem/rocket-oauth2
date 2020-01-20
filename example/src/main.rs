#![feature(proc_macro_hygiene, decl_macro)]
extern crate dotenv;
#[macro_use]
extern crate rocket;
extern crate rocket_oauth2;

use rocket::http::RawStr;
use rocket::response::Redirect;
use rocket::Request;
use rocket::State;
use rocket_oauth2::{OAuthConfiguration, OAuthUser};

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/secret")]
fn secret(user: OAuthUser) -> &'static str {
    "Secret"
}

#[get("/secret")]
fn secret_no_auth() -> &'static str {
    "Uh oh"
}

fn main() {
    dotenv::dotenv().ok();
    rocket::ignite()
        .manage(OAuthConfiguration {
            client_id: dotenv::var("CLIENT_ID").unwrap(),
            client_secret: dotenv::var("CLIENT_SECRET").unwrap(),
            extra_scopes: vec![],
            redirect_uri: "http://localhost:8000/oauth/login".to_string(),
        })
        .mount("/", routes![index, secret, rocket_oauth2::login])
        .register(catchers![rocket_oauth2::not_authorized])
        .launch();
}
