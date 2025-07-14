package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

// Define a context key for storing the user
type contextKey string

const userContextKey contextKey = "user"

// getUserHierarchyLevel fetches the hierarchy level for a given role name
func (apiCfg *apiConfig) getUserHierarchyLevel(ctx context.Context, roleName string) (int32, error) {
	role, err := apiCfg.DB.GetRoleByName(ctx, roleName)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("role '%s' not found", roleName)
		}
		return 0, fmt.Errorf("database error fetching role: %w", err)
	}
	return role.HierarchyLevel, nil
}

// isHigherOrEqualRole checks if roleA has a hierarchy level greater than or equal to roleB
func (apiCfg *apiConfig) isHigherOrEqualRole(ctx context.Context, roleA, roleB string) (bool, error) {
	levelA, err := apiCfg.getUserHierarchyLevel(ctx, roleA)
	if err != nil {
		return false, err
	}
	levelB, err := apiCfg.getUserHierarchyLevel(ctx, roleB)
	if err != nil {
		return false, err
	}
	return levelA >= levelB, nil
}

// middlewareAuth authenticates the user and attaches the user object to the request context
// This function now conforms to chi.Middleware signature: func(http.Handler) http.Handler
func (apiCfg *apiConfig) middlewareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Attach the user object to the request context
		ctx = context.WithValue(r.Context(), userContextKey, user)
		r = r.WithContext(ctx)

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

func (apiCfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		RoleName string `json:"role_name"` // Optional role for creation
	}
	decoder := json.NewDecoder(r.Body)

	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error parsing JSON: %v", err))
		return
	}

	// Determine the role for the new user
	newRoleName := "User" // Default role
	if params.RoleName != "" {
		newRoleName = params.RoleName
	}

	// Check if the role exists
	_, err = apiCfg.DB.GetRoleByName(r.Context(), newRoleName)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, 400, fmt.Sprintf("Invalid role specified: '%s'", newRoleName))
			return
		}
		respondWithError(w, 500, fmt.Sprintf("Database error checking role: %v", err))
		return
	}

	// Authorization check for assigning roles higher than 'User'
	// This route is public, so we need to check if an authenticated user is making the request
	// and if they have the necessary permissions to assign a non-default role.
	authedUser, ok := r.Context().Value(userContextKey).(database.User)
	if ok { // If an authenticated user is making the request
		if newRoleName != "User" {
			canAssign, err := apiCfg.isHigherOrEqualRole(r.Context(), authedUser.RoleName, newRoleName)
			if err != nil {
				respondWithError(w, 500, fmt.Sprintf("Error checking role hierarchy: %v", err))
				return
			}
			if !canAssign || (authedUser.RoleName == "Moderator" && newRoleName != "User") {
				respondWithError(w, 403, fmt.Sprintf("Unauthorized to create user with role '%s'", newRoleName))
				return
			}
		}
	} else { // If an unauthenticated user is making the request, they can only create 'User' role
		if newRoleName != "User" {
			respondWithError(w, 403, "Unauthorized to create user with a non-default role as an unauthenticated user")
			return
		}
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
		RoleName:     newRoleName, // Assign the determined role
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

// Helper function to get the authenticated user from context
func getAuthenticatedUser(r *http.Request) (database.User, error) {
	user, ok := r.Context().Value(userContextKey).(database.User)
	if !ok {
		return database.User{}, errors.New("authenticated user not found in context")
	}
	return user, nil
}

// handlerGetUser retrieves the authenticated user's details
func (apiCfg *apiConfig) handlerGetUser(w http.ResponseWriter, r *http.Request) {
	user, err := getAuthenticatedUser(r)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	respondWithJSON(w, 200, databaseUserToUser(user))
}

// handlerGetAllUsers retrieves all users, respecting role hierarchy
func (apiCfg *apiConfig) handlerGetAllUsers(w http.ResponseWriter, r *http.Request) {
	authedUser, err := getAuthenticatedUser(r)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	// Only Admin and SuperAdmin can view all users
	isAuthedUserAdminOrSuperAdmin, err := apiCfg.isHigherOrEqualRole(r.Context(), authedUser.RoleName, "Admin")
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error checking role hierarchy: %v", err))
		return
	}
	if !isAuthedUserAdminOrSuperAdmin {
		respondWithError(w, 403, "Unauthorized to view all users")
		return
	}

	users, err := apiCfg.DB.GetAllUsers(r.Context())
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Database error fetching users: %v", err))
		return
	}

	// Filter users based on hierarchy
	var filteredUsers []User
	authedUserLevel, err := apiCfg.getUserHierarchyLevel(r.Context(), authedUser.RoleName)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error getting authenticated user's role level: %v", err))
		return
	}

	for _, user := range users {
		userRoleLevel, err := apiCfg.getUserHierarchyLevel(r.Context(), user.RoleName)
		if err != nil {
			log.Printf("Warning: Could not get hierarchy level for user %s role %s: %v", user.ID, user.RoleName, err)
			continue // Skip this user if role level cannot be determined
		}

		// An authenticated user can only see users with a strictly lower hierarchy level,
		// or users with the same level if they are themselves.
		// SuperAdmin can see everyone.
		if authedUser.RoleName == "SuperAdmin" || userRoleLevel < authedUserLevel {
			filteredUsers = append(filteredUsers, databaseUserToUser(user))
		} else if userRoleLevel == authedUserLevel && user.ID == authedUser.ID {
			// Allow user to see their own details in the list if their role is not lower
			filteredUsers = append(filteredUsers, databaseUserToUser(user))
		}
	}

	respondWithJSON(w, 200, filteredUsers)
}

// handlerUpdateUser updates a user's details, respecting role hierarchy
func (apiCfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	authedUser, err := getAuthenticatedUser(r)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	userIDStr := strings.TrimPrefix(r.URL.Path, "/v1/users/")
	targetUserID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondWithError(w, 400, "Invalid user ID format")
		return
	}

	type updateParams struct {
		Name     *string `json:"name"`
		Password *string `json:"password"`
		RoleName *string `json:"role_name"`
	}
	decoder := json.NewDecoder(r.Body)
	params := updateParams{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Error parsing JSON: %v", err))
		return
	}

	// Fetch the target user to be updated
	targetUser, err := apiCfg.DB.GetUserByID(r.Context(), targetUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, 404, "Target user not found")
			return
		}
		respondWithError(w, 500, fmt.Sprintf("Database error fetching target user: %v", err))
		return
	}

	// Authorization check: User cannot update themselves to a higher role, or update users with higher/equal roles
	canManage, err := apiCfg.isHigherOrEqualRole(r.Context(), authedUser.RoleName, targetUser.RoleName)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error checking role hierarchy: %v", err))
		return
	}
	if !canManage && authedUser.ID != targetUserID { // Cannot manage someone with higher/equal role unless it's yourself
		respondWithError(w, 403, "Unauthorized to update this user")
		return
	}

	// Prevent a user from changing their own role to a higher level
	if authedUser.ID == targetUserID && params.RoleName != nil {
		isNewRoleHigherOrEqual, err := apiCfg.isHigherOrEqualRole(r.Context(), *params.RoleName, authedUser.RoleName)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Error checking new role hierarchy: %v", err))
			return
		}
		if isNewRoleHigherOrEqual && *params.RoleName != authedUser.RoleName {
			respondWithError(w, 403, "Unauthorized to elevate your own role")
			return
		}
	}

	// Prevent a user from assigning a role higher than their own to another user
	if authedUser.ID != targetUserID && params.RoleName != nil {
		isAssigningHigherThanSelf, err := apiCfg.isHigherOrEqualRole(r.Context(), *params.RoleName, authedUser.RoleName)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Error checking assigned role hierarchy: %v", err))
			return
		}
		if isAssigningHigherThanSelf && *params.RoleName != authedUser.RoleName {
			respondWithError(w, 403, fmt.Sprintf("Unauthorized to assign role '%s'", *params.RoleName))
			return
		}
	}

	// Prepare update parameters
	updateName := targetUser.Name
	if params.Name != nil {
		updateName = *params.Name
	}

	updatePasswordHash := targetUser.PasswordHash
	if params.Password != nil {
		newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Password), bcrypt.DefaultCost)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Failed to hash new password: %v", err))
			return
		}
		updatePasswordHash = string(newHashedPassword)
	}

	updateRoleName := targetUser.RoleName
	if params.RoleName != nil {
		// Verify the new role exists
		_, err = apiCfg.DB.GetRoleByName(r.Context(), *params.RoleName)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, 400, fmt.Sprintf("Invalid role specified: '%s'", *params.RoleName))
				return
			}
			respondWithError(w, 500, fmt.Sprintf("Database error checking new role: %v", err))
			return
		}
		updateRoleName = *params.RoleName
	}

	updatedUser, err := apiCfg.DB.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:           targetUserID,
		UpdatedAt:    time.Now().UTC(),
		Name:         updateName,
		PasswordHash: updatePasswordHash,
		RoleName:     updateRoleName,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			respondWithError(w, 409, fmt.Sprintf("User with name '%s' already exists", updateName))
			return
		}
		respondWithError(w, 500, fmt.Sprintf("Failed to update user: %v", err))
		return
	}

	respondWithJSON(w, 200, databaseUserToUser(updatedUser))
}

// handlerDeleteUser deletes a user, respecting role hierarchy
func (apiCfg *apiConfig) handlerDeleteUser(w http.ResponseWriter, r *http.Request) {
	authedUser, err := getAuthenticatedUser(r)
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	userIDStr := strings.TrimPrefix(r.URL.Path, "/v1/users/")
	targetUserID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondWithError(w, 400, "Invalid user ID format")
		return
	}

	// Prevent a user from deleting themselves
	if authedUser.ID == targetUserID {
		respondWithError(w, 403, "Unauthorized to delete your own account")
		return
	}

	// Fetch the target user to be deleted
	targetUser, err := apiCfg.DB.GetUserByID(r.Context(), targetUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, 404, "Target user not found")
			return
		}
		respondWithError(w, 500, fmt.Sprintf("Database error fetching target user: %v", err))
		return
	}

	// Authorization check: User can only delete users with a strictly lower hierarchy level
	canDelete, err := apiCfg.isHigherOrEqualRole(r.Context(), authedUser.RoleName, targetUser.RoleName)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Error checking role hierarchy: %v", err))
		return
	}
	if !canDelete {
		respondWithError(w, 403, "Unauthorized to delete this user")
		return
	}

	err = apiCfg.DB.DeleteUser(r.Context(), targetUserID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Failed to delete user: %v", err))
		return
	}

	respondWithJSON(w, 200, map[string]string{"message": "User deleted successfully"})
}
