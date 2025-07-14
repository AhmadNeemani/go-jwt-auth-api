package main

import (
	"time"

	"github.com/AhmadNeemani/test/internal/database"
	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
	RoleName  string    `json:"role_name"` // Added role_name
}

func databaseUserToUser(dbUser database.User) User {
	return User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Name:      dbUser.Name,
		RoleName:  dbUser.RoleName, // Map the new field
	}
}

// LoginResponse structure
type LoginResponse struct {
	User        User   `json:"user"`
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// RefreshTokenResponse structure
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// You can add other models here as your project grows (e.g., Feed, Post, FeedFollow)
// For this initial project, we're focusing on user and auth.
