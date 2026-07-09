// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"strings"
	"testing"
	"time"
)

func TestCreateAPIKey(t *testing.T) {
	db := setupAuthTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	apiKey, cleartext, err := CreateAPIKey(ctx, db, "test-key", user.ID, nil, nil)
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}
	if apiKey.ID == "" {
		t.Error("expected non-empty ID")
	}
	if apiKey.Name != "test-key" {
		t.Errorf("expected name 'test-key', got %q", apiKey.Name)
	}
	if apiKey.UserID != user.ID {
		t.Errorf("expected UserID %q, got %q", user.ID, apiKey.UserID)
	}
	if !apiKey.Active {
		t.Error("expected key to be active")
	}
	if !strings.HasPrefix(cleartext, "fdo_") {
		t.Errorf("expected cleartext to start with 'fdo_', got %q", cleartext)
	}
	if len(apiKey.Prefix) != 6 {
		t.Errorf("expected prefix length 6, got %d", len(apiKey.Prefix))
	}
	if cleartext[4:10] != apiKey.Prefix {
		t.Errorf("expected prefix %q, got %q", cleartext[4:10], apiKey.Prefix)
	}
}

func TestFindAPIKeysByPrefix(t *testing.T) {
	db := setupAuthTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	_, cleartext, err := CreateAPIKey(ctx, db, "test-key", user.ID, nil, nil)
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	prefix := cleartext[4:10]
	keys, err := FindAPIKeysByPrefix(ctx, db, prefix)
	if err != nil {
		t.Fatalf("FindAPIKeysByPrefix failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestCreateAPIKeyWithExpiration(t *testing.T) {
	db := setupAuthTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	expiry := time.Now().Add(24 * time.Hour)
	apiKey, _, err := CreateAPIKey(ctx, db, "expiring-key", user.ID, nil, &expiry)
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}
	if apiKey.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
}

func TestCreateAPIKeyWithScopes(t *testing.T) {
	db := setupAuthTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	scopes := []string{"vouchers:read"}
	apiKey, _, err := CreateAPIKey(ctx, db, "limited-key", user.ID, scopes, nil)
	if err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}
	got := apiKey.ScopesList()
	if len(got) != 1 || got[0] != "vouchers:read" {
		t.Errorf("expected scopes [vouchers:read], got %v", got)
	}
}
