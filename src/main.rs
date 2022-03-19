use log::info;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::Mutex;
use warp::Filter;

mod handlers;
mod models;

type UsersDb = Arc<Mutex<HashMap<String, models::User>>>;

#[tokio::main]
async fn main() {
    log4rs::init_file("logconfig.yml", Default::default()).expect("Log config file not found.");
    info!("Starting server...");
    let users_db: UsersDb = Arc::new(Mutex::new(HashMap::new()));

    let root = warp::path::end().map(|| "Welcome to the Rust REST API");

    let user_route = warp::path("user")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_users_db(users_db.clone()))
        .and_then(handlers::create_user);

    let routes = root.or(user_route).with(warp::cors().allow_any_origin());

    warp::serve(routes).run(([127, 0, 0, 1], 5000)).await;
}

fn with_users_db(
    users_db: UsersDb,
) -> impl Filter<Extract = (UsersDb,), Error = Infallible> + Clone {
    warp::any().map(move || users_db.clone())
}
