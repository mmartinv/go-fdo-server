// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"context"
	"errors"
)

type contextKey struct{}

var ErrInvalidCredentials = errors.New("invalid credentials")

type Identity struct {
	Subject    string
	Name       string
	AuthMethod string
	Roles      []string
	Scopes     []string
	Metadata   map[string]string
}

func (i *Identity) HasAllScopes(required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := make(map[string]struct{}, len(i.Scopes))
	for _, s := range i.Scopes {
		have[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := have[r]; !ok {
			return false
		}
	}
	return true
}

func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}
