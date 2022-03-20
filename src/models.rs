use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone)]
pub struct User {
    pub user_id: usize,
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}