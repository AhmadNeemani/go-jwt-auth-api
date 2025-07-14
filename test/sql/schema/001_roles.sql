-- +goose Up
CREATE TABLE roles (
    name TEXT PRIMARY KEY,
    hierarchy_level INT UNIQUE NOT NULL
);

-- Insert default roles
INSERT INTO roles (name, hierarchy_level) VALUES
('User', 1),
('Moderator', 2),
('Admin', 3),
('SuperAdmin', 4);

-- +goose Down
DROP TABLE roles;