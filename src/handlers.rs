use crate::{models, UsersDb, security};
use log::{error, info};
use warp::{
    http::{Response, StatusCode}, Reply, Rejection,
};

pub async fn create_user(user: models::CreateUser, users_db: UsersDb) -> std::result::Result<impl Reply, Rejection> {
    info!("Create user, received UserData: {:?}", user);
    let mut local_db = users_db.lock().await;

    if local_db.contains_key(&user.username) {
        error!("User already exists");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("User already exists".to_string()));
    }

    info!("Adding user to the database...");
    let key_count = local_db.keys().len();
    let created_user = models::User {
        user_id: key_count,
        username: user.username,
        password: security::get_hashed_password(&user.password),
        role: user.role,
    };
    local_db.insert(created_user.username.clone(), created_user.clone());

    info!("User {} added.", &created_user.username);
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(serde_json::to_string(&created_user).unwrap()))
}

pub async fn login(login_user: models::LoginUser, users_db: UsersDb) -> std::result::Result<impl Reply, Rejection> {
    info!("Received login request...");
    let cur_user_db = users_db.lock().await;
    let user = match cur_user_db.get(&login_user.username) {
        Some(k) => k,
        None => {
            error!("User '{}' not found in database", &login_user.username);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("login failed".to_string()));
        }
    };

    info!("User found, verifying password...");
    if !security::verify_password(&login_user.password, &user.password) {
        error!("Password incorrect for user: {}", &login_user.username);
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("login failed".to_string()));
    }

    info!("Login success!");
    let token = security::get_jwt_for_user(user);
    Ok(Response::builder().status(StatusCode::OK).body(token))
}