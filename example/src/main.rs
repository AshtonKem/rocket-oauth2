#![feature(proc_macro_hygiene, decl_macro)]
extern crate dotenv;
#[macro_use]
extern crate rocket;
extern crate rocket_oauth2;
use rocket_oauth2::{OAuthConfiguration, OAuthUser};

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/secret")]
fn secret(_user: OAuthUser) -> &'static str {
    "Secret"
}

#[get("/secret", rank = 2)]
fn secret_no_auth() -> &'static str {
    panic!("This should never happen");
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
        .mount(
            "/",
            routes![
                index,
                secret,
                secret_no_auth,
                rocket_oauth2::login,
                rocket_oauth2::logout
            ],
        )
        .register(catchers![rocket_oauth2::not_authorized])
        .launch();
}
