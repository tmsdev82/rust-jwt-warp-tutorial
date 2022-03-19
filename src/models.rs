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
