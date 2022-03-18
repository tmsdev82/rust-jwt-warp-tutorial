use warp::Filter;
use log::info;

#[tokio::main]
async fn main() {
    log4rs::init_file("logconfig.yml", Default::default()).expect("Log config file not found.");
    info!("Starting server...");
    let root = warp::path::end().map(|| { "Welcome to the Rust REST API"});
    
    let routes = root.with(warp::cors().allow_any_origin());

    warp::serve(routes).run(([127,0,0,1], 5000)).await;
}