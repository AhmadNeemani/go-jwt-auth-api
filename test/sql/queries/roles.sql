-- name: GetRoleByName :one
SELECT name, hierarchy_level FROM roles WHERE name = $1;
