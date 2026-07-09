// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"context"
	"net/http"
)

type Authenticator interface {
	Name() string
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
