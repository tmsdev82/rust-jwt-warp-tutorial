use log::error;
use serde::Serialize;
use std::convert::Infallible;
use thiserror::Error;
use warp::{http::StatusCode, reply::WithStatus, Rejection, Reply};

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("invalid credentials")]
    InvalidCredentialsError,
    #[error("user exists")]
    UserExistsError(String),
    #[error("invalid jwt token")]
    InvalidJWTTokenError,
    #[error("jwt token creation error")]
    JWTTokenCreationError,
    #[error("authorization header required")]
    AuthHeaderRequiredError,
    #[error("invalid auth header")]
    InvalidAuthHeaderError,
    #[error("not authorized")]
    NotAuthorizedError,
}

impl warp::reject::Reject for CustomError {}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    message: String,
    status: String,
}

pub fn reply_with_status(status_code: StatusCode, message: &str) -> WithStatus<impl Reply> {
    let json = warp::reply::json(&ErrorResponse {
        status: status_code.to_string(),
        message: message.to_string(),
    });

    return warp::reply::with_status(json, status_code);
}

pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    if err.is_not_found() {
        return Ok(reply_with_status(StatusCode::NOT_FOUND, "Not Found"));
    }

    if let Some(e) = err.find::<CustomError>() {
        match e {
            CustomError::InvalidCredentialsError => {
                return Ok(reply_with_status(StatusCode::FORBIDDEN, &e.to_string()));
            },
            CustomError::UserExistsError(username) => {
                return Ok(reply_with_status(StatusCode::BAD_REQUEST, &format!("User: {} already exists", username)));
            },
            CustomError::NotAuthorizedError => {
                return Ok(reply_with_status(StatusCode::UNAUTHORIZED, &e.to_string()));
            },
            CustomError::InvalidJWTTokenError => {
                return Ok(reply_with_status(StatusCode::UNAUTHORIZED, &e.to_string()));
            },
            CustomError::JWTTokenCreationError => {
                return Ok(reply_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"));
            },
            _ => {
                return Ok(reply_with_status(StatusCode::BAD_REQUEST, &e.to_string()));
            }
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        return Ok(reply_with_status(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
        ));
    }

    error!("unhandled error: {:?}", err);
    return Ok(reply_with_status(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error",
    ));
}
