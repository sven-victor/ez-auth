# EZ-Auth

EZ-Auth is a user authorization management system built with Golang for the backend and React for the frontend. It uses LDAP for user and application data sources, with additional data stored in relational databases (SQLite, MySQL, etc.).

## Demo
- https://sso.ez-auth.org/
- username: demo
- password: 12345678

## Features

- **Application Management**: Create, delete, and modify applications. Applications are implemented based on LDAP, where each application is an LDAP entry. Additional data (such as icons, status, roles, etc.) is stored in a relational database.
- **User Management**: Create, delete, and modify LDAP user entries.
- **User Authorization**: Implement user authorization based on LDAP's memberOf, with additional support for role assignment when authorizing users to applications.
- **OIDC Provider**: The system supports providing OIDC Provider functionality for third-party systems, returning user information with an additional role field.

## Tech Stack

### Backend
- Go
- Gin Web Framework
- LDAP
- SQLite/MySQL
- github.com/sven-victor/ez-console (Core Framework)

### Frontend
- React
- TypeScript
- Vite
- Ant Design
- React Query
- React Router
- i18next

## Project Structure

```
.
├── cmd/                    # Main application entry points
├── internal/              # Private application and library code
│   ├── api/              # HTTP API controllers
│   ├── service/          # Business logic layer
│   ├── middleware/       # HTTP middleware
│   ├── model/           # Data models
│   └── util/            # Utility functions
└── web/                 # Frontend React application
    ├── src/
    │   ├── api/        # API request related code
    │   ├── components/ # Reusable components
    │   ├── contexts/   # React Context related code
    │   ├── hooks/      # Custom React Hooks
    │   ├── pages/      # Page components
    │   ├── routes/     # Route configuration
    │   ├── types/      # TypeScript type definitions
    │   └── utils/      # Utility functions
```

## Building and Running

### Prerequisites
- Go 1.20 or later
- Node.js 18 or later
- pnpm
- LDAP server
- SQLite or MySQL

### Installation & Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/sven-victor/ez-auth.git
    cd ez-auth
    ```

2.  **Build :**
    ```bash
    # Clean up compiled object files and recompile
    make clean build
    ```

2.  **Running :**
    ```
    # <encrypt key>is a global encryption key
    dist/server --global.encrypt-key=<encrypt key>
    ```
    *\<encrypt key> formatted as a string of 8, 16, 24, or 32 bytes, used for encrypting and decrypting sensitive data. Please do not change it arbitrarily after running to avoid causing previous data to be unable to decrypt.*

## Configuration

- The application can be configured via the `config.yaml` file. Example:
    ```yaml
    # dist/server --global.encrypt-key=12345678 --config config.yaml
    server:
      host: "0.0.0.0"
      port: 8080
      mode: "debug"
      read_timeout: 10s
      write_timeout: 10s
      shutdown_timeout: 10s

    database:
      driver: "sqlite"
      path: "ez-console.db"
    ```
- Alternatively, you can specify certain configuration parameters through startup parameters.
    ```bash
    dist/server \
        --global.encrypt-key=12345678 \
        --database.driver=mysql \
        --database.host=1.1.1.1 \
        --database.username=ez-console \
        --database.password=ez-console-password \
        --log.level=debug \
        --log.format=lucy
    ```
