-- name: CreateUser :one
INSERT INTO users(id, created_at, updated_at, name, password_hash, role_name)
VALUES($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByID :one
SELECT id, created_at, updated_at, name, password_hash, role_name FROM users WHERE id = $1;

-- name: GetUserByName :one
SELECT id, created_at, updated_at, name, password_hash, role_name FROM users WHERE name = $1;

-- name: UpdateUser :one
UPDATE users SET
    updated_at = $1,
    name = $2,
    password_hash = $3,
    role_name = $4
WHERE id = $5
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: GetAllUsers :many
SELECT id, created_at, updated_at, name, password_hash, role_name FROM users;
