package main

import (
	"context" 
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AhmadNeemani/test/internal/database"
	"github.com/AhmadNeemani/test/internal/database/auth"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt" 
)


type authedHandler func(http.ResponseWriter, *http.Request, database.User)


func (apiCfg *apiConfig) middlewareAuth(handler authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 403, fmt.Sprintf("Authentication error: %v", err))
			return
		}

		claims, err := auth.ValidateJWT(tokenString)
		if err != nil {
			respondWithError(w, 401, fmt.Sprintf("Invalid token: %v", err))
			return
		}

		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			respondWithError(w, 400, "Invalid User ID in token claims")
			return
		}

	
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := apiCfg.DB.GetUserByID(ctx, userID)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, 404, "User not found")
				return
			}
			respondWithError(w, 500, fmt.Sprintf("Database error fetching user: %v", err))
			return
		}

		handler(w, r, user)
	}
}

func (apiCfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)

	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error parsing JSON: %v", err))
		return
	}


	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Failed to hash password: %v", err))
		return
	}

	user, err := apiCfg.DB.CreateUser(r.Context(), database.CreateUserParams{
		ID:           uuid.New(),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		Name:         params.Name,
		PasswordHash: string(hashedPassword), 
	})
	if err != nil {
		
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			respondWithError(w, 409, fmt.Sprintf("User with name '%s' already exists", params.Name))
			return
		}
		respondWithError(w, 400, fmt.Sprintf("Couldn't create user: %v", err))
		return
	}

	respondWithJSON(w, 201, databaseUserToUser(user))
}

func (apiCfg *apiConfig) handlerUserLogin(w http.ResponseWriter, r *http.Request) {
	type loginParams struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := loginParams{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error parsing JSON: %v", err))
		return
	}

	user, err := apiCfg.DB.GetUserByName(r.Context(), params.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, 401, "Invalid credentials") 
			return
		}
		respondWithError(w, 500, fmt.Sprintf("Database error during login: %v", err))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(params.Password))
	if err != nil {
		respondWithError(w, 401, "Invalid credentials") 
		return
	}

	
	accessToken, err := auth.GenerateJWT(user.ID.String(), time.Hour) 
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Failed to generate access token: %v", err))
		return
	}

	refreshToken, err := auth.GenerateJWT(user.ID.String(), time.Hour*24*7) 
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Failed to generate refresh token: %v", err))
		return
	}

	_, err = apiCfg.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).UTC(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		log.Printf("Warning: Failed to save refresh token for user %s: %v", user.ID, err)
	}

	respondWithJSON(w, 200, LoginResponse{
		User:        databaseUserToUser(user),
		AccessToken: accessToken,
		RefreshToken: refreshToken, 
	})
}

func (apiCfg *apiConfig) handlerRefreshToken(w http.ResponseWriter, r *http.Request) {
	type refreshRequest struct {
		RefreshToken string `json:"refresh_token"`
	}
	decoder := json.NewDecoder(r.Body)
	params := refreshRequest{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error parsing JSON: %v", err))
		return
	}

	claims, err := auth.ValidateJWT(params.RefreshToken)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Invalid or expired refresh token: %v", err))
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, 400, "Invalid User ID in token claims")
		return
	}

	dbRefreshToken, err := apiCfg.DB.GetRefreshToken(r.Context(), params.RefreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, 401, "Refresh token not found or already used")
			return
		}
		respondWithError(w, 500, fmt.Sprintf("Database error fetching refresh token: %v", err))
		return
	}

	if dbRefreshToken.ExpiresAt.Before(time.Now().UTC()) {
		apiCfg.DB.DeleteRefreshToken(r.Context(), params.RefreshToken)
		respondWithError(w, 401, "Refresh token expired")
		return
	}

	if dbRefreshToken.UserID != userID {
		respondWithError(w, 401, "Refresh token user ID mismatch")
		return
	}

	err = apiCfg.DB.DeleteRefreshToken(r.Context(), params.RefreshToken)
	if err != nil {
		log.Printf("Warning: Failed to delete used refresh token %s for user %s: %v", params.RefreshToken, userID, err)
	}

	newAccessToken, err := auth.GenerateJWT(userID.String(), time.Hour)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Failed to generate new access token: %v", err))
		return
	}

	newRefreshToken, err := auth.GenerateJWT(userID.String(), time.Hour*24*7)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Failed to generate new refresh token: %v", err))
		return
	}

	_, err = apiCfg.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     newRefreshToken,
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).UTC(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		log.Printf("Warning: Failed to save new refresh token for user %s: %v", userID, err)
	}

	respondWithJSON(w, 200, RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
}


func (apiCfg *apiConfig) handlerGetUser(w http.ResponseWriter, r *http.Request, user database.User) {
	respondWithJSON(w, 200, databaseUserToUser(user))
}

