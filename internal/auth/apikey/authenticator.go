// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/fido-device-onboard/go-fdo-server/internal/auth"
	"github.com/fido-device-onboard/go-fdo-server/internal/state"
)

const (
	headerName     = "X-API-Key"
	keyPrefix      = "fdo_"
	minKeyLen      = 10
	prefixStartIdx = 4
	prefixEndIdx   = 10
)

var _ auth.Authenticator = (*APIKeyAuthenticator)(nil)

type APIKeyAuthenticator struct {
	db *gorm.DB
	wg sync.WaitGroup
}

func New(db *gorm.DB) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{db: db}
}

func (a *APIKeyAuthenticator) Wait() {
	a.wg.Wait()
}

func (a *APIKeyAuthenticator) Name() string { return "api-key" }

func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	key := r.Header.Get(headerName)
	if key == "" {
		return nil, nil
	}

	if !strings.HasPrefix(key, keyPrefix) || len(key) < minKeyLen {
		return nil, auth.ErrInvalidCredentials
	}

	prefix := key[prefixStartIdx:prefixEndIdx]

	candidates, err := state.FindAPIKeysByPrefix(ctx, a.db, prefix)
	if err != nil {
		slog.Error("Failed to look up API keys by prefix", "prefix", prefix, "error", err)
		return nil, auth.ErrInvalidCredentials
	}

	hash := sha256.Sum256([]byte(key))

	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare(candidate.HashedKey, hash[:]) != 1 {
			continue
		}

		user, err := state.GetUserByID(ctx, a.db, candidate.UserID)
		if err != nil {
			slog.Error("Failed to look up API key owner", "user_id", candidate.UserID, "error", err)
			return nil, auth.ErrInvalidCredentials
		}
		if !user.Active {
			return nil, auth.ErrInvalidCredentials
		}

		if candidate.ExpiresAt != nil && candidate.ExpiresAt.Before(time.Now()) {
			slog.Debug("API key expired", "prefix", prefix)
			return nil, auth.ErrInvalidCredentials
		}

		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			state.UpdateAPIKeyLastUsed(bgCtx, a.db, candidate.ID)
		}()

		scopes, err := a.resolveScopes(ctx, &candidate)
		if err != nil {
			return nil, auth.ErrInvalidCredentials
		}

		roles, err := state.GetUserRoles(ctx, a.db, candidate.UserID)
		if err != nil {
			slog.Error("Failed to look up user roles", "user_id", candidate.UserID, "error", err)
			return nil, auth.ErrInvalidCredentials
		}
		var roleNames []string
		for _, r := range roles {
			roleNames = append(roleNames, r.Name)
		}

		return &auth.Identity{
			Subject:    candidate.UserID,
			Name:       user.Name,
			AuthMethod: "api-key",
			Roles:      roleNames,
			Scopes:     scopes,
			Metadata:   map[string]string{"api_key_prefix": prefix, "api_key_name": candidate.Name},
		}, nil
	}

	return nil, auth.ErrInvalidCredentials
}

func (a *APIKeyAuthenticator) resolveScopes(ctx context.Context, apiKey *state.APIKey) ([]string, error) {
	userScopes, err := state.GetUserScopes(ctx, a.db, apiKey.UserID)
	if err != nil {
		return nil, err
	}

	keyScopes := apiKey.ScopesList()
	if len(keyScopes) == 0 {
		return userScopes, nil
	}

	userScopeSet := make(map[string]struct{}, len(userScopes))
	for _, s := range userScopes {
		userScopeSet[s] = struct{}{}
	}

	var effective []string
	for _, s := range keyScopes {
		if _, ok := userScopeSet[s]; ok {
			effective = append(effective, s)
		}
	}
	return effective, nil
}
