// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"context"
	"testing"
)

func TestHasAllScopes(t *testing.T) {
	id := &Identity{
		Scopes: []string{"vouchers:read", "vouchers:write", "vouchers:delete", "device-ca:read"},
	}

	tests := []struct {
		name     string
		required []string
		want     bool
	}{
		{"single present scope", []string{"vouchers:read"}, true},
		{"multiple present scopes", []string{"vouchers:read", "vouchers:write"}, true},
		{"all present scopes", []string{"vouchers:delete"}, true},
		{"missing scope", []string{"vouchers:extend"}, false},
		{"one present one missing", []string{"vouchers:read", "vouchers:extend"}, false},
		{"nil required", nil, true},
		{"empty required", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := id.HasAllScopes(tt.required)
			if got != tt.want {
				t.Errorf("HasAllScopes(%v) = %v, want %v", tt.required, got, tt.want)
			}
		})
	}
}

func TestIdentityContext(t *testing.T) {
	id := &Identity{Subject: "user-123", Name: "admin"}
	ctx := ContextWithIdentity(context.Background(), id)

	found := IdentityFromContext(ctx)
	if found == nil {
		t.Fatal("expected identity in context, got nil")
	}
	if found.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got %q", found.Subject)
	}

	empty := IdentityFromContext(context.Background())
	if empty != nil {
		t.Errorf("expected nil identity from empty context, got %v", empty)
	}
}
