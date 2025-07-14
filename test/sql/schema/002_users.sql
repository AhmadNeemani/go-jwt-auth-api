-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    name TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE RESTRICT DEFAULT 'User'
);

-- +goose Down
DROP TABLE users;