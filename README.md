# JSON Web Token security for Rust REST API example

This repository contains an example of how to implement JWT security for a REST API. The implementation uses the Rust programming language. For the REST API the warp crate is used.

The REST API implementation has endpoints for: creating a user, logging in, an endpoint only accessible by logged in users (using a token), and an endpoint only accessible to users with the admin role.

An `HashMap` is used as an in memory database.

How and why the code is built like this is explained in a tutorial on my blog: [JWT security for a Rust REST API: how to](https://tms-dev-blog.com/jwt-security-for-a-rust-rest-api/)


# Running the program

A file called `.env` needs to be present in the root of the project with a line 

```
JWT_SECRET=our_secret
```

Please create this `.env` file before running the project.

The program is run using the command: `cargo run` or `cargo run --release`.

Creating a user with a user role can be done using the following request:

```bash
curl -X POST 'localhost:5000/user' -H "Content-Type: application/json" -d '{"username": "testuser", "password": "testpass", "role": "user"}'
```

Then to login:

```bash
curl -X POST 'localhost:5000/login' -H "Content-Type: application/json" -d '{"username": "testuser", "password": "testpass"}'
```

This will return a string representing the JWT data, which can then be used to access protected endpoints. For example, to access the private endpoint:

```bash
curl -X GET 'localhost:5000/private' -H 'Authorization: Bearer <token string here>'
```

Creating a user with an admin role can be done using the following request:

```bash
curl -X POST 'localhost:5000/user' -H "Content-Type: application/json" -d '{"username": "testadmin", "password": "adminpass", "role": "admin"}'
```

Then to login:

```bash
curl -X POST 'localhost:5000/login' -H "Content-Type: application/json" -d '{"username": "testadmin", "password": "adminpass"}'
```

The admin only endpoint can be accessed here:

```bash
curl -X GET 'localhost:5000/admin_only' -H 'Authorization: Bearer <token string here>'
```