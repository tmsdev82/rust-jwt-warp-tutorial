use crate::models;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};

const JWT_SECRET: &[u8; 10] = b"our_secret";

pub fn get_hashed_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = Scrypt
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    password_hash
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(password_hash).unwrap();

    Scrypt
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn get_jwt_for_user(user: &models::User) -> String {
    let expiration_time = Utc::now()
        .checked_add_signed(Duration::seconds(60))
        .expect("invalid timestamp")
        .timestamp();
    let user_claims = models::Claims {
        sub: user.username.clone(),
        role: user.role.clone(),
        exp: expiration_time as usize,
    };

    let token = match encode(
        &Header::default(),
        &user_claims,
        &EncodingKey::from_secret(JWT_SECRET),
    ) {
        Ok(t) => t,
        Err(_) => panic!(),
    };

    token
}
