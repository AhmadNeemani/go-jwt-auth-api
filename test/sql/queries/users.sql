-- name: CreateUser :one
INSERT INTO users(id, created_at, updated_at, name, password_hash)
VALUES($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByName :one
SELECT * FROM users WHERE name = $1;