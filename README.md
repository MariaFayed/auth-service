# Auth Service - README

## Description
This service handles user authentication and authorization using **Keycloak**, with support for:
- User login and registration
- Role assignment (user/admin)
- JWT-based authentication
- Refresh token handling (stored as httpOnly cookies)
- Logout support
- Global exception handling with logging to AWS CloudWatch

---

## Tech Stack
- **NestJS**
- **Keycloak**
- **Axios**
- **Cookie-parser**
- **AWS CloudWatch (winston-cloudwatch)**

---

## Setup Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Set Environment Variables
Create a `.env` file you will find it attached with .env-auth-service:

---

## Running the App
```bash
npm run start:dev
```

### Using Docker

---

## Keycloak Setup

### Start Keycloak with Docker
Find attached docker-compose.yml use it to run a container that setup keycloack + keycloack postgres db + monogodb

### Import Realm
You can import your realm using the Keycloak Admin Console manually :
Find attached exported realm to start running the app

---

## API Endpoints

Swagger is used at api/docs 

### POST `/auth/login`
```json
{
  "email": "jojo@jojo.com",
  "password": "P@ssw0rd"
}
```

Returns:
```json
{
  "access_token": "...",
  "refresh_token": "[cookie]",
  "expires_in": 300,
  "name": "John Doe"
}
```

### POST `/auth/signup`
```json
{
  "email": "example@example.com",
  "password": "P@ssw0rd!",
  "firstName": "John",
  "lastName": "Doe",
  "role": "user"
}
```

### POST `/auth/refresh`
No body needed. Uses refresh_token from cookie.

### POST `/auth/logout`
Clears refresh token cookie.

### GET `/auth/verify`
Returns token validity if `Authorization: Bearer <token>` header is present.

---

## Notes
- Use a user with user role  to access Courses page, use user with admin role to access companies page
example use jojo@jojo.com password P@ssw0rd to access Coursers
use admin@admin.com password P@ssw0rd to access Companies
---

## License
MIT
