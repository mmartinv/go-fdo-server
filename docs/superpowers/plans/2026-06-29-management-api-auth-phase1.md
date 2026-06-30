# Management API Auth Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add authentication (API key) and authorization (RBAC + scopes) to the FDO server management API, with a pluggable framework for future auth mechanisms.

**Architecture:** Middleware chain (AuthN → AuthZ) inserted between rate limiter and OpenAPI validation. Scopes parsed from `x-required-scopes` OpenAPI extensions at startup. API key authenticator as the first pluggable mechanism. Auth disabled by default for backward compatibility.

**Tech Stack:** Go 1.26, GORM (SQLite/PostgreSQL), `crypto/sha256` + `crypto/subtle` (stdlib), `github.com/getkin/kin-openapi`, Cobra/Viper, oapi-codegen

## Global Constraints

- Module path: `github.com/fido-device-onboard/go-fdo-server`
- Existing GORM model pattern: models in `internal/state/`, init functions return `(*State, error)`, `AutoMigrate` called in init
- Existing middleware pattern: `func(http.Handler) http.Handler` closures in `internal/middleware/`
- Existing config pattern: structs with `mapstructure` tags in `internal/config/`, validated via `.Validate()` methods
- Existing CLI pattern: Cobra commands in `cmd/`, Viper for config binding
- OpenAPI specs: per-resource YAML in `api/v2/<resource>/openapi.yaml`, merged into `openapi.json` via `go:generate npx openapi-format`
- FDO protocol endpoints (`/fdo/101/msg/*`, `/fdo/200/msg/*`), `/health`, `/api/docs/*`, `/api/openapi.json` are NEVER subject to management API auth
- Default behavior when `auth` is not configured: all endpoints open (backward compatible)
- SPDX header: `// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.` + `// SPDX-License-Identifier: Apache 2.0`
- Error responses: `{"message": "..."}` JSON format, matching existing `errorResponse` struct pattern

---

### Task 1: Database Models for Users, Roles, and API Keys

**Files:**
- Create: `internal/state/user.go`
- Create: `internal/state/role.go`
- Create: `internal/state/apikey.go`
- Create: `internal/state/auth.go`
- Create: `internal/state/user_test.go`
- Create: `internal/state/role_test.go`
- Create: `internal/state/auth_test.go`
- Create: `internal/state/apikey_test.go`

**Interfaces:**
- Consumes: `gorm.io/gorm` (existing dependency)
- Produces:
  - `type User struct` — GORM model with ID (UUID string), Name, Email, Active, CreatedAt, UpdatedAt
  - `type Role struct` — GORM model with ID (UUID string), Name, Description, BuiltIn (bool), CreatedAt, UpdatedAt
  - `type UserRole struct` — join table with UserID, RoleID
  - `type RoleScope struct` — GORM model with RoleID, Scope (string)
  - `type APIKey struct` — GORM model with ID (UUID string), Prefix (6 chars), HashedKey ([]byte), Name, UserID (FK), Scopes (JSON string slice), ExpiresAt (*time.Time), Active (bool), LastUsedAt (*time.Time), CreatedAt, UpdatedAt
  - `func InitAuthDB(ctx context.Context, db *gorm.DB) error` — runs AutoMigrate for all auth models
  - `func CreateUser(ctx context.Context, db *gorm.DB, name, email string) (*User, error)`
  - `func GetUserByID(ctx context.Context, db *gorm.DB, id string) (*User, error)`
  - `func GetUserRoles(ctx context.Context, db *gorm.DB, userID string) ([]Role, error)`
  - `func GetUserScopes(ctx context.Context, db *gorm.DB, userID string) ([]string, error)`
  - `func CreateRole(ctx context.Context, db *gorm.DB, name, description string, builtIn bool, scopes []string) (*Role, error)`
  - `func AssignRoleToUser(ctx context.Context, db *gorm.DB, userID, roleID string) error`
  - `func CreateAPIKey(ctx context.Context, db *gorm.DB, name, userID string, scopes []string, expiresAt *time.Time) (*APIKey, string, error)` — returns model + cleartext key
  - `func FindAPIKeysByPrefix(ctx context.Context, db *gorm.DB, prefix string) ([]APIKey, error)`
  - `func UpdateAPIKeyLastUsed(ctx context.Context, db *gorm.DB, id string)`
  - `func UserCount(ctx context.Context, db *gorm.DB) (int64, error)`

- [ ] **Step 1: Write test for User CRUD**

Create `internal/state/user_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, InitAuthDB(t.Context(), db))
	return db
}

func TestCreateUser(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "admin", user.Name)
	assert.Equal(t, "admin@example.com", user.Email)
	assert.True(t, user.Active)
}

func TestGetUserByID(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	created, err := CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	found, err := GetUserByID(ctx, db, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "admin", found.Name)
}

func TestGetUserByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	_, err := GetUserByID(t.Context(), db, "nonexistent")
	assert.Error(t, err)
}

func TestUserCount(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	count, err := UserCount(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	_, err = CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	count, err = UserCount(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/state/ -run "TestCreateUser|TestGetUserByID|TestUserCount" -v`
Expected: FAIL — `InitAuthDB`, `CreateUser`, `GetUserByID`, `UserCount` not defined

- [ ] **Step 3: Implement User model and operations**

Create `internal/state/user.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        string    `gorm:"type:varchar(36);primaryKey"`
	Name      string    `gorm:"type:varchar(255);not null"`
	Email     string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	Active    bool      `gorm:"type:boolean;not null;default:true"`
	CreatedAt time.Time `gorm:"autoCreateTime:milli"`
	UpdatedAt time.Time `gorm:"autoUpdateTime:milli"`
}

func (User) TableName() string { return "users" }

func CreateUser(ctx context.Context, db *gorm.DB, name, email string) (*User, error) {
	user := &User{
		ID:     uuid.New().String(),
		Name:   name,
		Email:  email,
		Active: true,
	}
	if err := db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}

func GetUserByID(ctx context.Context, db *gorm.DB, id string) (*User, error) {
	var user User
	if err := db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

func UserCount(ctx context.Context, db *gorm.DB) (int64, error) {
	var count int64
	if err := db.WithContext(ctx).Model(&User{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return count, nil
}
```

- [ ] **Step 4: Run user tests to verify they pass**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/state/ -run "TestCreateUser|TestGetUserByID|TestUserCount" -v`
Expected: PASS

- [ ] **Step 5: Write test for Role CRUD**

Create `internal/state/role_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateRole(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	role, err := CreateRole(ctx, db, "admin", "Full access", true, []string{"vouchers:read", "vouchers:write", "vouchers:delete"})
	require.NoError(t, err)
	assert.NotEmpty(t, role.ID)
	assert.Equal(t, "admin", role.Name)
	assert.True(t, role.BuiltIn)
}

func TestAssignRoleAndGetScopes(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	role, err := CreateRole(ctx, db, "admin", "Full access", true, []string{"vouchers:read", "vouchers:write", "vouchers:delete"})
	require.NoError(t, err)

	user, err := CreateUser(ctx, db, "testuser", "test@example.com")
	require.NoError(t, err)

	err = AssignRoleToUser(ctx, db, user.ID, role.ID)
	require.NoError(t, err)

	roles, err := GetUserRoles(ctx, db, user.ID)
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)

	scopes, err := GetUserScopes(ctx, db, user.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"vouchers:read", "vouchers:write", "vouchers:delete"}, scopes)
}
```

- [ ] **Step 6: Implement Role model and operations**

Create `internal/state/role.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Role struct {
	ID          string    `gorm:"type:varchar(36);primaryKey"`
	Name        string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	Description string    `gorm:"type:text"`
	BuiltIn     bool      `gorm:"type:boolean;not null;default:false"`
	CreatedAt   time.Time `gorm:"autoCreateTime:milli"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime:milli"`
}

func (Role) TableName() string { return "roles" }

type RoleScope struct {
	RoleID string `gorm:"type:varchar(36);not null;primaryKey"`
	Scope  string `gorm:"type:varchar(255);not null;primaryKey"`
}

func (RoleScope) TableName() string { return "role_scopes" }

type UserRole struct {
	UserID string `gorm:"type:varchar(36);not null;primaryKey"`
	RoleID string `gorm:"type:varchar(36);not null;primaryKey"`
}

func (UserRole) TableName() string { return "user_roles" }

func CreateRole(ctx context.Context, db *gorm.DB, name, description string, builtIn bool, scopes []string) (*Role, error) {
	role := &Role{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		BuiltIn:     builtIn,
	}
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(role).Error; err != nil {
			return fmt.Errorf("failed to create role: %w", err)
		}
		for _, scope := range scopes {
			if err := tx.Create(&RoleScope{RoleID: role.ID, Scope: scope}).Error; err != nil {
				return fmt.Errorf("failed to create role scope: %w", err)
			}
		}
		return nil
	})
	return role, err
}

func FindOrCreateRole(ctx context.Context, db *gorm.DB, name, description string, builtIn bool, scopes []string) (*Role, error) {
	var existing Role
	err := db.WithContext(ctx).Where("name = ?", name).First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check for existing role %q: %w", name, err)
	}
	return CreateRole(ctx, db, name, description, builtIn, scopes)
}

func AssignRoleToUser(ctx context.Context, db *gorm.DB, userID, roleID string) error {
	if err := db.WithContext(ctx).Create(&UserRole{UserID: userID, RoleID: roleID}).Error; err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}
	return nil
}

func GetUserRoles(ctx context.Context, db *gorm.DB, userID string) ([]Role, error) {
	var roles []Role
	if err := db.WithContext(ctx).Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	return roles, nil
}

func GetUserScopes(ctx context.Context, db *gorm.DB, userID string) ([]string, error) {
	var scopes []string
	if err := db.WithContext(ctx).Model(&RoleScope{}).
		Joins("JOIN user_roles ON user_roles.role_id = role_scopes.role_id").
		Where("user_roles.user_id = ?", userID).
		Distinct().
		Pluck("scope", &scopes).Error; err != nil {
		return nil, fmt.Errorf("failed to get user scopes: %w", err)
	}
	return scopes, nil
}
```

- [ ] **Step 7: Run role tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/state/ -run "TestCreateRole|TestAssignRole" -v`
Expected: PASS

- [ ] **Step 8: Write test for APIKey CRUD**

Create `internal/state/apikey_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAPIKey(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	apiKey, cleartext, err := CreateAPIKey(ctx, db, "test-key", user.ID, nil, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, apiKey.ID)
	assert.Equal(t, "test-key", apiKey.Name)
	assert.Equal(t, user.ID, apiKey.UserID)
	assert.True(t, apiKey.Active)
	assert.True(t, strings.HasPrefix(cleartext, "fdo_"))
	assert.Len(t, apiKey.Prefix, 6)
	assert.Equal(t, cleartext[4:10], apiKey.Prefix)
}

func TestFindAPIKeysByPrefix(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	_, cleartext, err := CreateAPIKey(ctx, db, "test-key", user.ID, nil, nil)
	require.NoError(t, err)

	prefix := cleartext[4:10]
	keys, err := FindAPIKeysByPrefix(ctx, db, prefix)
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestCreateAPIKeyWithExpiration(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	expiry := time.Now().Add(24 * time.Hour)
	apiKey, _, err := CreateAPIKey(ctx, db, "expiring-key", user.ID, nil, &expiry)
	require.NoError(t, err)
	assert.NotNil(t, apiKey.ExpiresAt)
}

func TestCreateAPIKeyWithScopes(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	user, err := CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	scopes := []string{"vouchers:read"}
	apiKey, _, err := CreateAPIKey(ctx, db, "limited-key", user.ID, scopes, nil)
	require.NoError(t, err)
	assert.Equal(t, scopes, apiKey.ScopesList())
}
```

- [ ] **Step 9: Implement APIKey model and operations**

Create `internal/state/apikey.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	apiKeyPrefix    = "fdo_"
	apiKeyRandBytes = 32
	apiKeyPrefixLen = 6
	base62Chars     = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

type APIKey struct {
	ID         string     `gorm:"type:varchar(36);primaryKey"`
	Prefix     string     `gorm:"type:varchar(6);not null;index"`
	HashedKey  []byte     `gorm:"type:blob;not null"`
	Name       string     `gorm:"type:varchar(255);not null"`
	UserID     string     `gorm:"type:varchar(36);not null;index"`
	Scopes     string     `gorm:"type:text"`
	ExpiresAt  *time.Time `gorm:"index"`
	Active     bool       `gorm:"type:boolean;not null;default:true"`
	LastUsedAt *time.Time
	CreatedAt  time.Time `gorm:"autoCreateTime:milli"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime:milli"`
}

func (APIKey) TableName() string { return "api_keys" }

func (a *APIKey) ScopesList() []string {
	if a.Scopes == "" {
		return nil
	}
	var scopes []string
	if err := json.Unmarshal([]byte(a.Scopes), &scopes); err != nil {
		return nil
	}
	return scopes
}

func generateAPIKey() (string, error) {
	var b strings.Builder
	b.WriteString(apiKeyPrefix)
	max := big.NewInt(int64(len(base62Chars)))
	for i := 0; i < apiKeyRandBytes; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		b.WriteByte(base62Chars[n.Int64()])
	}
	return b.String(), nil
}

func CreateAPIKey(ctx context.Context, db *gorm.DB, name, userID string, scopes []string, expiresAt *time.Time) (*APIKey, string, error) {
	cleartext, err := generateAPIKey()
	if err != nil {
		return nil, "", err
	}

	hash := sha256.Sum256([]byte(cleartext))
	hashed := hash[:]

	var scopesJSON string
	if len(scopes) > 0 {
		b, err := json.Marshal(scopes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal scopes: %w", err)
		}
		scopesJSON = string(b)
	}

	apiKey := &APIKey{
		ID:        uuid.New().String(),
		Prefix:    cleartext[len(apiKeyPrefix) : len(apiKeyPrefix)+apiKeyPrefixLen],
		HashedKey: hashed,
		Name:      name,
		UserID:    userID,
		Scopes:    scopesJSON,
		ExpiresAt: expiresAt,
		Active:    true,
	}

	if err := db.WithContext(ctx).Create(apiKey).Error; err != nil {
		return nil, "", fmt.Errorf("failed to create API key: %w", err)
	}
	return apiKey, cleartext, nil
}

func FindAPIKeysByPrefix(ctx context.Context, db *gorm.DB, prefix string) ([]APIKey, error) {
	var keys []APIKey
	if err := db.WithContext(ctx).Where("prefix = ? AND active = ?", prefix, true).Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to find API keys by prefix: %w", err)
	}
	return keys, nil
}

func UpdateAPIKeyLastUsed(ctx context.Context, db *gorm.DB, id string) {
	now := time.Now()
	if err := db.WithContext(ctx).Model(&APIKey{}).Where("id = ?", id).Update("last_used_at", now).Error; err != nil {
		slog.Warn("Failed to update API key last_used_at", "id", id, "error", err)
	}
}
```

- [ ] **Step 10: Implement InitAuthDB**

Create `internal/state/auth.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"
)

func InitAuthDB(ctx context.Context, db *gorm.DB) error {
	if err := db.WithContext(ctx).AutoMigrate(&User{}, &Role{}, &RoleScope{}, &UserRole{}, &APIKey{}); err != nil {
		return fmt.Errorf("failed to migrate auth database schema: %w", err)
	}
	slog.Info("Auth database initialized successfully")
	return nil
}
```

- [ ] **Step 11: Add `google/uuid` dependency**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go get github.com/google/uuid`

- [ ] **Step 12: Run all auth state tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/state/ -run "TestCreateUser|TestGetUser|TestUserCount|TestCreateRole|TestAssignRole|TestCreateAPIKey|TestFindAPIKeys" -v`
Expected: ALL PASS

- [ ] **Step 13: Commit**

```bash
git add internal/state/user.go internal/state/role.go internal/state/apikey.go internal/state/auth.go internal/state/user_test.go internal/state/role_test.go internal/state/apikey_test.go
git commit -m "feat: add database models for users, roles, and API keys"
```

---

### Task 2: Auth Identity and Authenticator Interface

**Files:**
- Create: `internal/auth/identity.go`
- Create: `internal/auth/authenticator.go`
- Create: `internal/auth/identity_test.go`

**Interfaces:**
- Consumes: nothing (standalone types)
- Produces:
  - `type Identity struct` — Subject, Name, AuthMethod, Roles, Scopes, Metadata
  - `func (i *Identity) HasAllScopes(required []string) bool`
  - `func IdentityFromContext(ctx context.Context) *Identity`
  - `func ContextWithIdentity(ctx context.Context, id *Identity) context.Context`
  - `type Authenticator interface` — `Name() string`, `Authenticate(ctx, r) (*Identity, error)`
  - `var ErrInvalidCredentials` — sentinel error (expired keys also return this to avoid leaking key validity)

- [ ] **Step 1: Write test for Identity scope checking**

Create `internal/auth/identity_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasAllScopes(t *testing.T) {
	id := &Identity{
		Scopes: []string{"vouchers:read", "vouchers:write", "vouchers:delete", "device-ca:read"},
	}

	assert.True(t, id.HasAllScopes([]string{"vouchers:read"}))
	assert.True(t, id.HasAllScopes([]string{"vouchers:read", "vouchers:write"}))
	assert.True(t, id.HasAllScopes([]string{"vouchers:delete"}))
	assert.False(t, id.HasAllScopes([]string{"vouchers:extend"}))
	assert.False(t, id.HasAllScopes([]string{"vouchers:read", "vouchers:extend"}))
	assert.True(t, id.HasAllScopes(nil))
	assert.True(t, id.HasAllScopes([]string{}))
}

func TestIdentityContext(t *testing.T) {
	id := &Identity{Subject: "user-123", Name: "admin"}
	ctx := ContextWithIdentity(context.Background(), id)

	found := IdentityFromContext(ctx)
	assert.NotNil(t, found)
	assert.Equal(t, "user-123", found.Subject)

	empty := IdentityFromContext(context.Background())
	assert.Nil(t, empty)
}
```

- [ ] **Step 2: Implement Identity and Authenticator**

Create `internal/auth/identity.go`:

```go
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
```

Create `internal/auth/authenticator.go`:

```go
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
```

- [ ] **Step 3: Run tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/auth/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/auth/identity.go internal/auth/authenticator.go internal/auth/identity_test.go
git commit -m "feat: add auth Identity model and Authenticator interface"
```

---

### Task 3: API Key Authenticator

**Files:**
- Create: `internal/auth/apikey/authenticator.go`
- Create: `internal/auth/apikey/authenticator_test.go`

**Interfaces:**
- Consumes: `auth.Authenticator` interface, `state.FindAPIKeysByPrefix`, `state.GetUserRoles`, `state.GetUserScopes`, `state.UpdateAPIKeyLastUsed`
- Produces: `type APIKeyAuthenticator struct` implementing `auth.Authenticator`

- [ ] **Step 1: Write test for API key authenticator**

Create `internal/auth/apikey/authenticator_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package apikey

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo-server/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, state.InitAuthDB(t.Context(), db))
	return db
}

func TestAuthenticate_NoHeader(t *testing.T) {
	db := setupTestDB(t)
	authn := New(db)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	id, err := authn.Authenticate(r.Context(), r)
	assert.Nil(t, id)
	assert.NoError(t, err)
}

func TestAuthenticate_InvalidFormat(t *testing.T) {
	db := setupTestDB(t)
	authn := New(db)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", "bad_key")
	id, err := authn.Authenticate(r.Context(), r)
	assert.Nil(t, id)
	assert.Error(t, err)
}

func TestAuthenticate_ValidKey(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	authn := New(db)

	user, err := state.CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)
	role, err := state.CreateRole(ctx, db, "admin", "Admin", true, []string{"vouchers:read", "vouchers:write", "vouchers:delete"})
	require.NoError(t, err)
	require.NoError(t, state.AssignRoleToUser(ctx, db, user.ID, role.ID))

	_, cleartext, err := state.CreateAPIKey(ctx, db, "test-key", user.ID, nil, nil)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", cleartext)
	id, authErr := authn.Authenticate(r.Context(), r)
	require.NoError(t, authErr)
	require.NotNil(t, id)
	assert.Equal(t, user.ID, id.Subject)
	assert.Equal(t, "api-key", id.AuthMethod)
	assert.ElementsMatch(t, []string{"vouchers:read", "vouchers:write", "vouchers:delete"}, id.Scopes)
}

func TestAuthenticate_ExpiredKey(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	authn := New(db)

	user, err := state.CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)

	expired := time.Now().Add(-1 * time.Hour)
	_, cleartext, err := state.CreateAPIKey(ctx, db, "expired-key", user.ID, nil, &expired)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", cleartext)
	id, authErr := authn.Authenticate(r.Context(), r)
	assert.Nil(t, id)
	assert.Error(t, authErr)
}

func TestAuthenticate_InactiveUser(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	authn := New(db)

	user, err := state.CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)
	role, err := state.CreateRole(ctx, db, "admin", "Admin", true, []string{"vouchers:read"})
	require.NoError(t, err)
	require.NoError(t, state.AssignRoleToUser(ctx, db, user.ID, role.ID))

	_, cleartext, err := state.CreateAPIKey(ctx, db, "test-key", user.ID, nil, nil)
	require.NoError(t, err)

	require.NoError(t, db.WithContext(ctx).Model(&state.User{}).Where("id = ?", user.ID).Update("active", false).Error)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", cleartext)
	id, authErr := authn.Authenticate(r.Context(), r)
	assert.Nil(t, id)
	assert.Error(t, authErr)
}

func TestAuthenticate_ScopedKey(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	authn := New(db)

	user, err := state.CreateUser(ctx, db, "admin", "admin@example.com")
	require.NoError(t, err)
	role, err := state.CreateRole(ctx, db, "admin", "Admin", true, []string{"vouchers:read", "vouchers:write", "vouchers:delete", "device-ca:read"})
	require.NoError(t, err)
	require.NoError(t, state.AssignRoleToUser(ctx, db, user.ID, role.ID))

	_, cleartext, err := state.CreateAPIKey(ctx, db, "limited-key", user.ID, []string{"vouchers:read"}, nil)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", cleartext)
	id, authErr := authn.Authenticate(r.Context(), r)
	require.NoError(t, authErr)
	require.NotNil(t, id)
	assert.Equal(t, []string{"vouchers:read"}, id.Scopes)
}
```

- [ ] **Step 2: Implement API key authenticator**

Create `internal/auth/apikey/authenticator.go`:

```go
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
```

- [ ] **Step 3: Run tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/auth/apikey/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/auth/apikey/authenticator.go internal/auth/apikey/authenticator_test.go
git commit -m "feat: add API key authenticator"
```

---

### Task 4: AuthN and AuthZ Middleware

**Files:**
- Create: `internal/auth/middleware.go`
- Create: `internal/auth/middleware_test.go`

**Interfaces:**
- Consumes: `auth.Authenticator` interface, `auth.IdentityFromContext`, `auth.ContextWithIdentity`
- Produces:
  - `func AuthNMiddleware(authenticators []Authenticator, excludedPaths []string) func(http.Handler) http.Handler`
  - `func AuthZMiddleware(routeScopes map[string][]string) func(http.Handler) http.Handler`

- [ ] **Step 1: Write tests for AuthN middleware**

Create `internal/auth/middleware_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockAuthenticator struct {
	name     string
	identity *Identity
	err      error
}

func (m *mockAuthenticator) Name() string { return m.name }
func (m *mockAuthenticator) Authenticate(_ context.Context, _ *http.Request) (*Identity, error) {
	return m.identity, m.err
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthNMiddleware_ExcludedPath(t *testing.T) {
	mw := AuthNMiddleware(nil, []string{"/health"})
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthNMiddleware_ExcludedPathExactMatch(t *testing.T) {
	mw := AuthNMiddleware(nil, []string{"/health"})
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/health-check", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthNMiddleware_ExcludedPathPrefixMatch(t *testing.T) {
	mw := AuthNMiddleware(nil, []string{"/api/docs/"})
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/api/docs/index.html", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthNMiddleware_NoAuthenticators(t *testing.T) {
	mw := AuthNMiddleware(nil, nil)
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/api/v2/vouchers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthNMiddleware_SuccessfulAuth(t *testing.T) {
	id := &Identity{Subject: "user-1", Scopes: []string{"vouchers:read"}}
	authn := &mockAuthenticator{name: "mock", identity: id}
	mw := AuthNMiddleware([]Authenticator{authn}, nil)
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/api/v2/vouchers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthNMiddleware_InvalidCredentials(t *testing.T) {
	authn := &mockAuthenticator{name: "mock", err: errors.New("bad creds")}
	mw := AuthNMiddleware([]Authenticator{authn}, nil)
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/api/v2/vouchers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthNMiddleware_FallThrough(t *testing.T) {
	skip := &mockAuthenticator{name: "skip", identity: nil, err: nil}
	id := &Identity{Subject: "user-1"}
	match := &mockAuthenticator{name: "match", identity: id}
	mw := AuthNMiddleware([]Authenticator{skip, match}, nil)
	handler := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/api/v2/vouchers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthZMiddleware_Allowed(t *testing.T) {
	routeScopes := map[string][]string{
		"GET /vouchers": {"vouchers:read"},
	}
	mw := AuthZMiddleware(routeScopes)

	id := &Identity{Scopes: []string{"vouchers:read", "vouchers:write", "vouchers:delete"}}
	inner := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/vouchers", nil)
	r = r.WithContext(ContextWithIdentity(r.Context(), id))
	w := httptest.NewRecorder()
	inner.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthZMiddleware_Forbidden(t *testing.T) {
	routeScopes := map[string][]string{
		"DELETE /vouchers/{guid}": {"vouchers:delete"},
	}
	mw := AuthZMiddleware(routeScopes)

	id := &Identity{Scopes: []string{"vouchers:read"}}
	inner := mw(okHandler())

	r := httptest.NewRequest(http.MethodDelete, "/vouchers/abc123", nil)
	r = r.WithContext(ContextWithIdentity(r.Context(), id))
	w := httptest.NewRecorder()
	inner.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthZMiddleware_NoScopesRequired(t *testing.T) {
	mw := AuthZMiddleware(map[string][]string{})

	id := &Identity{Scopes: []string{}}
	inner := mw(okHandler())

	r := httptest.NewRequest(http.MethodGet, "/unprotected", nil)
	r = r.WithContext(ContextWithIdentity(r.Context(), id))
	w := httptest.NewRecorder()
	inner.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
```

- [ ] **Step 2: Implement AuthN and AuthZ middleware**

Create `internal/auth/middleware.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

var defaultExcludedPaths = []string{
	"/fdo/101/msg/",   // prefix match (trailing /)
	"/fdo/200/msg/",   // prefix match (trailing /)
	"/health",         // exact match
	"/api/docs/",      // prefix match (trailing /)
	"/api/openapi.json", // exact match
}

func AuthNMiddleware(authenticators []Authenticator, excludedPaths []string) func(http.Handler) http.Handler {
	allExcluded := make([]string, 0, len(defaultExcludedPaths)+len(excludedPaths))
	allExcluded = append(allExcluded, defaultExcludedPaths...)
	allExcluded = append(allExcluded, excludedPaths...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isExcluded(path.Clean(r.URL.Path), allExcluded) {
				next.ServeHTTP(w, r)
				return
			}

			for _, authn := range authenticators {
				identity, err := authn.Authenticate(r.Context(), r)
				if err != nil {
					slog.Debug("Authentication failed", "authenticator", authn.Name(), "error", err)
					writeAuthError(w, http.StatusUnauthorized, "authentication failed")
					return
				}
				if identity != nil {
					ctx := ContextWithIdentity(r.Context(), identity)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			writeAuthError(w, http.StatusUnauthorized, "authentication required")
		})
	}
}

func AuthZMiddleware(routeScopes map[string][]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := IdentityFromContext(r.Context())
			if identity == nil {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			required := lookupRequiredScopes(r.Method, r.URL.Path, routeScopes)
			if len(required) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			if !identity.HasAllScopes(required) {
				slog.Debug("Authorization denied",
					"subject", identity.Subject,
					"required", required,
					"have", identity.Scopes,
					"path", r.URL.Path,
				)
				writeAuthError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isExcluded(path string, excluded []string) bool {
	for _, entry := range excluded {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(path, entry) {
				return true
			}
		} else {
			if path == entry {
				return true
			}
		}
	}
	return false
}

func lookupRequiredScopes(method, path string, routeScopes map[string][]string) []string {
	for pattern, scopes := range routeScopes {
		if matchRoute(method, path, pattern) {
			return scopes
		}
	}
	return nil
}

func matchRoute(method, path, pattern string) bool {
	parts := strings.SplitN(pattern, " ", 2)
	if len(parts) != 2 {
		return false
	}
	patternMethod, patternPath := parts[0], parts[1]

	if method != patternMethod {
		return false
	}

	return matchPath(path, patternPath)
}

func matchPath(path, pattern string) bool {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(pathParts) != len(patternParts) {
		return false
	}

	for i, pp := range patternParts {
		if strings.HasPrefix(pp, "{") && strings.HasSuffix(pp, "}") {
			continue
		}
		if pp != pathParts[i] {
			return false
		}
	}
	return true
}

type authErrorResponse struct {
	Message string `json:"message"`
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(authErrorResponse{Message: message})
}
```

- [ ] **Step 3: Run tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/auth/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "feat: add AuthN and AuthZ middleware"
```

---

### Task 5: OpenAPI Scope Parser

**Files:**
- Create: `internal/auth/scopes.go`
- Create: `internal/auth/scopes_test.go`

**Interfaces:**
- Consumes: `github.com/getkin/kin-openapi/openapi3` (existing dependency)
- Produces: `func ParseRouteScopes(specJSON []byte) (map[string][]string, error)`

- [ ] **Step 1: Write tests for scope parsing**

Create `internal/auth/scopes_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRouteScopes(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0"},
		"paths": {
			"/api/v2/vouchers": {
				"get": {
					"operationId": "ListVouchers",
					"x-required-scopes": ["vouchers:read"],
					"responses": {"200": {"description": "OK"}}
				},
				"post": {
					"operationId": "ImportVouchers",
					"x-required-scopes": ["vouchers:write"],
					"responses": {"201": {"description": "Created"}}
				}
			},
			"/api/v2/vouchers/{guid}": {
				"delete": {
					"operationId": "DeleteVoucher",
					"x-required-scopes": ["vouchers:delete"],
					"responses": {"204": {"description": "Deleted"}}
				}
			},
			"/health": {
				"get": {
					"operationId": "Health",
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`)

	scopes, err := ParseRouteScopes(spec)
	require.NoError(t, err)

	assert.Equal(t, []string{"vouchers:read"}, scopes["GET /vouchers"])
	assert.Equal(t, []string{"vouchers:write"}, scopes["POST /vouchers"])
	assert.Equal(t, []string{"vouchers:delete"}, scopes["DELETE /vouchers/{guid}"])
	_, hasHealth := scopes["GET /health"]
	assert.False(t, hasHealth)
}

func TestParseRouteScopes_NoExtension(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0"},
		"paths": {
			"/api/v2/resource": {
				"get": {
					"operationId": "GetResource",
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`)

	scopes, err := ParseRouteScopes(spec)
	require.NoError(t, err)
	assert.Empty(t, scopes)
}

func TestParseRouteScopes_MultipleScopes(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0"},
		"paths": {
			"/api/v2/admin": {
				"post": {
					"operationId": "AdminAction",
					"x-required-scopes": ["vouchers:read", "vouchers:delete"],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`)

	scopes, err := ParseRouteScopes(spec)
	require.NoError(t, err)
	assert.Equal(t, []string{"vouchers:read", "vouchers:delete"}, scopes["POST /admin"])
}
```

- [ ] **Step 2: Implement scope parser**

Create `internal/auth/scopes.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package auth

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

const requiredScopesExtension = "x-required-scopes"

func ParseRouteScopes(specJSON []byte) (map[string][]string, error) {
	spec, err := openapi3.NewLoader().LoadFromData(specJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	routeScopes := make(map[string][]string)

	for path, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			ext, ok := op.Extensions[requiredScopesExtension]
			if !ok {
				continue
			}

			scopeSlice, err := parseStringSliceExtension(ext)
			if err != nil {
				return nil, fmt.Errorf("invalid %s on %s %s: %w", requiredScopesExtension, method, path, err)
			}

			if len(scopeSlice) == 0 {
				continue
			}

			normalizedPath := path
			if stripped, ok := strings.CutPrefix(path, "/api/v2"); ok {
				normalizedPath = stripped
			}

			key := method + " " + normalizedPath
			routeScopes[key] = scopeSlice
			slog.Debug("Registered route scope", "route", key, "scopes", scopeSlice)
		}
	}

	return routeScopes, nil
}

func parseStringSliceExtension(ext interface{}) ([]string, error) {
	raw, ok := ext.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected array, got %T", ext)
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected string in array, got %T", v)
		}
		result = append(result, s)
	}
	return result, nil
}
```

- [ ] **Step 3: Run tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/auth/ -run "TestParseRouteScopes" -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/auth/scopes.go internal/auth/scopes_test.go
git commit -m "feat: add OpenAPI x-required-scopes parser"
```

---

### Task 6: Auth Configuration and Seed Logic

**Files:**
- Create: `internal/config/auth.go`
- Create: `internal/config/auth_test.go`
- Create: `internal/state/seed.go`
- Create: `internal/state/seed_test.go`
- Modify: `internal/config/server.go` — add `Auth AuthConfig` field

**Interfaces:**
- Consumes: `state.CreateUser`, `state.CreateRole`, `state.AssignRoleToUser`, `state.CreateAPIKey`, `state.UserCount`
- Produces:
  - `type AuthConfig struct` — Enabled, ExcludedPaths, Mechanisms, Seed
  - `func (a *AuthConfig) Validate() error`
  - `func SeedAuth(ctx context.Context, db *gorm.DB, cfg config.SeedConfig, serverScopes []string, force bool) (string, error)` — returns API key cleartext; all operations are atomic (single transaction)

- [ ] **Step 1: Write test for AuthConfig validation**

Create `internal/config/auth_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthConfig_Validate_Disabled(t *testing.T) {
	cfg := AuthConfig{Enabled: false}
	assert.NoError(t, cfg.Validate())
}

func TestAuthConfig_Validate_EnabledNoMechanisms(t *testing.T) {
	cfg := AuthConfig{Enabled: true}
	assert.Error(t, cfg.Validate())
}

func TestAuthConfig_Validate_EnabledWithAPIKey(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		Mechanisms: MechanismsConfig{
			APIKey: &APIKeyMechanismConfig{Enabled: true},
		},
	}
	assert.NoError(t, cfg.Validate())
}

func TestAuthConfig_Validate_EnabledAPIKeyDisabled(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		Mechanisms: MechanismsConfig{
			APIKey: &APIKeyMechanismConfig{Enabled: false},
		},
	}
	assert.Error(t, cfg.Validate())
}
```

- [ ] **Step 2: Implement AuthConfig**

Create `internal/config/auth.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package config

import (
	"errors"
	"log/slog"
)

type AuthConfig struct {
	Enabled       bool             `mapstructure:"enabled"`
	ExcludedPaths []string         `mapstructure:"excluded_paths"`
	Mechanisms    MechanismsConfig `mapstructure:"mechanisms"`
	Seed          *SeedConfig      `mapstructure:"seed"`
}

type MechanismsConfig struct {
	APIKey *APIKeyMechanismConfig `mapstructure:"api_key"`
}

type APIKeyMechanismConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type SeedConfig struct {
	Admin *SeedAdminConfig `mapstructure:"admin"`
}

type SeedAdminConfig struct {
	Name   string `mapstructure:"name"`
	Email  string `mapstructure:"email"`
	APIKey string `mapstructure:"api_key"`
}

func (a *AuthConfig) Validate() error {
	if !a.Enabled {
		slog.Debug("Auth is disabled")
		return nil
	}

	if !a.HasEnabledMechanism() {
		return errors.New("auth is enabled but no authentication mechanism is configured")
	}

	slog.Debug("Auth configuration validated", "mechanisms", a.enabledMechanismNames())
	return nil
}

func (a *AuthConfig) HasEnabledMechanism() bool {
	if a.Mechanisms.APIKey != nil && a.Mechanisms.APIKey.Enabled {
		return true
	}
	return false
}

func (a *AuthConfig) enabledMechanismNames() []string {
	var names []string
	if a.Mechanisms.APIKey != nil && a.Mechanisms.APIKey.Enabled {
		names = append(names, "api-key")
	}
	return names
}
```

- [ ] **Step 3: Update ServerConfig to include Auth**

Modify `internal/config/server.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package config

type ServerConfig struct {
	Log  LogConfig      `mapstructure:"log"`
	DB   DatabaseConfig `mapstructure:"db"`
	HTTP HTTPConfig     `mapstructure:"http"`
	Auth AuthConfig     `mapstructure:"auth"`
}
```

- [ ] **Step 4: Write test for seed logic**

Create `internal/state/seed_test.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo-server/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeedAuth_CreatesAdminUserAndKey(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	scopes := []string{"vouchers:read", "vouchers:write", "vouchers:delete", "vouchers:extend"}
	cfg := config.SeedConfig{
		Admin: &config.SeedAdminConfig{
			Name:  "admin",
			Email: "admin@example.com",
		},
	}

	apiKey, err := SeedAuth(ctx, db, cfg, scopes, false)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(apiKey, "fdo_"))

	count, _ := UserCount(ctx, db)
	assert.Equal(t, int64(1), count)
}

func TestSeedAuth_SkipsIfUsersExist(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	_, err := CreateUser(ctx, db, "existing", "existing@example.com")
	require.NoError(t, err)

	cfg := config.SeedConfig{
		Admin: &config.SeedAdminConfig{
			Name:  "admin",
			Email: "admin@example.com",
		},
	}

	apiKey, err := SeedAuth(ctx, db, cfg, nil, false)
	require.NoError(t, err)
	assert.Empty(t, apiKey)
}

func TestSeedAuth_ForceCreatesWhenUsersExist(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	scopes := []string{"vouchers:read"}

	cfg1 := config.SeedConfig{
		Admin: &config.SeedAdminConfig{Name: "admin", Email: "admin@example.com"},
	}
	_, err := SeedAuth(ctx, db, cfg1, scopes, false)
	require.NoError(t, err)

	cfg2 := config.SeedConfig{
		Admin: &config.SeedAdminConfig{Name: "admin2", Email: "admin2@example.com"},
	}
	apiKey, err := SeedAuth(ctx, db, cfg2, scopes, true)
	require.NoError(t, err)
	assert.NotEmpty(t, apiKey)

	count, _ := UserCount(ctx, db)
	assert.Equal(t, int64(2), count)
}

func TestSeedAuth_PresetAPIKey(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	cfg := config.SeedConfig{
		Admin: &config.SeedAdminConfig{
			Name:   "admin",
			Email:  "admin@example.com",
			APIKey: "fdo_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2",
		},
	}

	apiKey, err := SeedAuth(ctx, db, cfg, []string{"vouchers:read"}, false)
	require.NoError(t, err)
	assert.Equal(t, cfg.Admin.APIKey, apiKey)
}
```

- [ ] **Step 5: Implement seed logic**

Create `internal/state/seed.go`:

```go
// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo-server/internal/config"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func SeedAuth(ctx context.Context, db *gorm.DB, cfg config.SeedConfig, serverScopes []string, force bool) (string, error) {
	if cfg.Admin == nil {
		return "", nil
	}

	if !force {
		count, err := UserCount(ctx, db)
		if err != nil {
			return "", err
		}
		if count > 0 {
			slog.Info("Users already exist, skipping auth seed")
			return "", nil
		}
	}

	slog.Info("Seeding auth database with initial admin user")

	var cleartext string
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		adminScopes := append(serverScopes[:len(serverScopes):len(serverScopes)], "auth:manage")
		adminRole, err := FindOrCreateRole(ctx, tx, "admin", "Full administrative access", true, adminScopes)
		if err != nil {
			return fmt.Errorf("failed to create admin role: %w", err)
		}

		var operatorScopes []string
		for _, s := range serverScopes {
			if strings.HasSuffix(s, ":read") || strings.HasSuffix(s, ":write") || strings.HasSuffix(s, ":extend") {
				operatorScopes = append(operatorScopes, s)
			}
		}
		if _, err := FindOrCreateRole(ctx, tx, "operator", "Operational access (create/modify, no delete or auth management)", true, operatorScopes); err != nil {
			return fmt.Errorf("failed to create operator role: %w", err)
		}

		user, err := CreateUser(ctx, tx, cfg.Admin.Name, cfg.Admin.Email)
		if err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		if err := AssignRoleToUser(ctx, tx, user.ID, adminRole.ID); err != nil {
			return fmt.Errorf("failed to assign admin role: %w", err)
		}

		if cfg.Admin.APIKey != "" {
			if err := createPresetAPIKey(ctx, tx, user.ID, cfg.Admin.APIKey); err != nil {
				return err
			}
			cleartext = cfg.Admin.APIKey
			return nil
		}

		_, key, err := CreateAPIKey(ctx, tx, "admin-seed-key", user.ID, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to create admin API key: %w", err)
		}
		cleartext = key
		return nil
	})
	if err != nil {
		return "", err
	}

	return cleartext, nil
}

func createPresetAPIKey(ctx context.Context, db *gorm.DB, userID, cleartext string) error {
	if !strings.HasPrefix(cleartext, "fdo_") || len(cleartext) < 10 {
		return fmt.Errorf("invalid preset API key: must start with 'fdo_' and be at least 10 characters")
	}

	hash := sha256.Sum256([]byte(cleartext))
	hashed := hash[:]

	prefix := cleartext[4:10]
	apiKey := &APIKey{
		ID:        uuid.New().String(),
		Prefix:    prefix,
		HashedKey: hashed,
		Name:      "admin-seed-key",
		UserID:    userID,
		Active:    true,
	}

	if err := db.WithContext(ctx).Create(apiKey).Error; err != nil {
		return fmt.Errorf("failed to create preset API key: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Run all config and seed tests**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./internal/config/ -run "TestAuthConfig" -v && go test ./internal/state/ -run "TestSeedAuth" -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add internal/config/auth.go internal/config/auth_test.go internal/config/server.go internal/state/seed.go internal/state/seed_test.go
git commit -m "feat: add auth configuration and database seed logic"
```

---

### Task 7: OpenAPI `x-required-scopes` Annotations

**Files:**
- Modify: `api/v2/voucher/openapi.yaml` — add `x-required-scopes` to 6 operations
- Modify: `api/v2/deviceca/openapi.yaml` — add `x-required-scopes` to 4 operations
- Modify: `api/v2/rvinfo/openapi.yaml` — add `x-required-scopes` to 3 operations (read, write, delete)
- Modify: `api/v2/rvto2addr/openapi.yaml` — add `x-required-scopes` to 3 operations
- Modify: `api/v2/device/openapi.yaml` — add `x-required-scopes` to 1 operation

**Interfaces:**
- Consumes: Existing OpenAPI YAML files
- Produces: Same files with `x-required-scopes` annotations on each operation

- [ ] **Step 1: Add `x-required-scopes` to voucher API**

In `api/v2/voucher/openapi.yaml`, add to each operation right after `operationId`:

- `ListOwnershipVouchers` → `x-required-scopes: [vouchers:read]`
- `ImportOwnershipVouchers` → `x-required-scopes: [vouchers:write]`
- `GetOwnershipVoucherByGuid` → `x-required-scopes: [vouchers:read]`
- `DeleteOwnershipVoucher` → `x-required-scopes: [vouchers:delete]`
- `ExtendOwnershipVoucher` → `x-required-scopes: [vouchers:extend]`
- `VerifyOwnership` → `x-required-scopes: [vouchers:write]`

- [ ] **Step 2: Add `x-required-scopes` to deviceca API**

In `api/v2/deviceca/openapi.yaml`:

- `ListTrustedDeviceCACerts` → `x-required-scopes: [device-ca:read]`
- `ImportTrustedDeviceCACerts` → `x-required-scopes: [device-ca:write]`
- `GetTrustedDeviceCACertByFingerprint` → `x-required-scopes: [device-ca:read]`
- `DeleteTrustedDeviceCACert` → `x-required-scopes: [device-ca:delete]`

- [ ] **Step 3: Add `x-required-scopes` to rvinfo API**

In `api/v2/rvinfo/openapi.yaml`:

- `GetRendezvousInfo` → `x-required-scopes: [rvinfo:read]`
- `UpdateRendezvousInfo` → `x-required-scopes: [rvinfo:write]`
- `DeleteRendezvousInfo` → `x-required-scopes: [rvinfo:delete]`

- [ ] **Step 4: Add `x-required-scopes` to rvto2addr API**

In `api/v2/rvto2addr/openapi.yaml`:

- `GetRVTO2Addr` → `x-required-scopes: [rvto2addr:read]`
- `UpdateRVTO2Addr` → `x-required-scopes: [rvto2addr:write]`
- `DeleteRVTO2Addr` → `x-required-scopes: [rvto2addr:delete]`

- [ ] **Step 5: Add `x-required-scopes` to device API**

In `api/v2/device/openapi.yaml`:

- `ListDevices` → `x-required-scopes: [devices:read]`

- [ ] **Step 6: Regenerate merged OpenAPI JSON specs**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go generate ./api/v2/...`

- [ ] **Step 7: Commit**

```bash
git add api/v2/
git commit -m "feat: add x-required-scopes annotations to OpenAPI specs"
```

---

### Task 8: Wire Auth into Server Startup

**Files:**
- Modify: `api/v2/manufacturer/handler.go` — add auth middleware wiring
- Modify: `api/v2/owner/handler.go` — add auth middleware wiring
- Modify: `api/v2/rendezvous/handler.go` — add auth middleware wiring
- Modify: `internal/server/manufacturing.go` — call `InitAuthDB`, `SeedAuth`, pass auth config
- Modify: `internal/server/owner.go` — same
- Modify: `internal/server/rendezvous.go` — same

**Interfaces:**
- Consumes: `auth.AuthNMiddleware`, `auth.AuthZMiddleware`, `auth.ParseRouteScopes`, `apikey.New`, `state.InitAuthDB`, `state.SeedAuth`, `config.AuthConfig`
- Produces: Complete end-to-end auth pipeline wired into all three server types

- [ ] **Step 1: Define scope registries per server type**

Each handler package needs a function that returns its server-specific scopes. Add to each handler's `Handler()` method or as a package-level function. For the manufacturer handler (`api/v2/manufacturer/handler.go`), the auth middleware wraps the V2 management API mux:

```go
import (
	"github.com/fido-device-onboard/go-fdo-server/internal/auth"
	"github.com/fido-device-onboard/go-fdo-server/internal/auth/apikey"
	"github.com/fido-device-onboard/go-fdo-server/internal/config"
)
```

Update the `Handler()` method signature to accept auth config and return an error:

```go
func (m *Manufacturer) Handler(authCfg config.AuthConfig) (http.Handler, error) {
```

Inside `Handler()`, after building `mgmtAPIServeMuxV2` and before wrapping with validation middleware, add:

```go
var mgmtHandlerV2 http.Handler
if authCfg.Enabled {
    routeScopes, err := auth.ParseRouteScopes(openAPISpecJSON)
    if err != nil {
        return nil, fmt.Errorf("failed to parse route scopes: %w", err)
    }
    var authenticators []auth.Authenticator
    if authCfg.Mechanisms.APIKey != nil && authCfg.Mechanisms.APIKey.Enabled {
        authenticators = append(authenticators, apikey.New(m.DB))
    }
    authN := auth.AuthNMiddleware(authenticators, authCfg.ExcludedPaths)
    authZ := auth.AuthZMiddleware(routeScopes)

    mgmtHandlerV2 = middleware.RateLimitMiddleware(rate.NewLimiter(2, 10),
        middleware.BodySizeMiddleware(10<<20,
            authN(authZ(validationMiddleware(mgmtAPIServeMuxV2)))))
} else {
    mgmtHandlerV2 = middleware.RateLimitMiddleware(rate.NewLimiter(2, 10),
        middleware.BodySizeMiddleware(10<<20,
            validationMiddleware(mgmtAPIServeMuxV2)))
}
```

Apply the same pattern to `api/v2/owner/handler.go` and `api/v2/rendezvous/handler.go`.

**Security-critical:** The V1 management API (`/api/v1/`) MUST also be wrapped with the auth middleware when auth is enabled. Without this, an attacker bypasses authentication entirely by using V1 endpoints. Apply the same `authN` middleware to the V1 mux:

```go
var mgmtHandlerV1 http.Handler
if authCfg.Enabled {
    mgmtHandlerV1 = authN(mgmtAPIServeMuxV1)
} else {
    mgmtHandlerV1 = mgmtAPIServeMuxV1
}
```

Note: V1 endpoints do not need `authZ` (scope checking) since they predate the scope model — `authN` alone ensures only authenticated users can access them. Scope-based authorization for V1 can be added if V1 is retained long-term.

- [ ] **Step 2: Update server startup to init auth DB and seed**

In `internal/server/manufacturing.go`, update `NewManufacturingServer` after DB init:

```go
if err := state.InitAuthDB(ctx, gormDB); err != nil {
    return nil, fmt.Errorf("failed to initialize auth database: %w", err)
}

if config.Auth.Enabled && config.Auth.Seed != nil {
    mfgScopes := []string{
        "vouchers:read", "vouchers:write", "vouchers:delete", "vouchers:extend",
        "rvinfo:read", "rvinfo:write", "rvinfo:delete",
    }
    apiKey, err := state.SeedAuth(ctx, gormDB, *config.Auth.Seed, mfgScopes, false)
    if err != nil {
        return nil, fmt.Errorf("failed to seed auth: %w", err)
    }
    if apiKey != "" {
        fmt.Fprintf(os.Stderr, "WARNING: Initial admin API key generated — save this key, it will not be shown again:\n%s\n", apiKey)
    }
}
```

Update the `Handler()` call to pass auth config:

```go
httpHandler, err := mfg.Handler(config.Auth)
if err != nil {
    return nil, fmt.Errorf("failed to build handler: %w", err)
}
```

Apply the same pattern to owner (with owner-specific scopes) and rendezvous (with rv-specific scopes).

- [ ] **Step 3: Add auth validation to manufacturing config Validate()**

In `internal/config/manufacturer.go`, add at the end of `Validate()`:

```go
if err := m.ServerConfig.Auth.Validate(); err != nil {
    return err
}
```

Do the same in `internal/config/owner.go` and `internal/config/rendezvous.go`.

- [ ] **Step 4: Run existing tests to verify backward compatibility**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go test ./... 2>&1 | tail -30`
Expected: ALL existing tests PASS (auth disabled by default)

- [ ] **Step 5: Write integration test for auth pipeline**

Create a test that starts a handler with auth enabled, makes requests with and without API keys, and verifies 401/403/200 responses. Add to a new test file alongside the manufacturer handler tests.

- [ ] **Step 6: Commit**

```bash
git add api/v2/manufacturer/handler.go api/v2/owner/handler.go api/v2/rendezvous/handler.go
git add internal/server/manufacturing.go internal/server/owner.go internal/server/rendezvous.go
git add internal/config/manufacturer.go internal/config/owner.go internal/config/rendezvous.go
git commit -m "feat: wire auth middleware into server startup"
```

---

### Task 9: CLI `init-admin` Command

**Files:**
- Modify: `cmd/manufacturing.go` — add `init-admin` subcommand
- Modify: `cmd/owner.go` — add `init-admin` subcommand
- Modify: `cmd/rendezvous.go` — add `init-admin` subcommand

**Interfaces:**
- Consumes: `config.*ServerConfig`, `state.InitAuthDB`, `state.SeedAuth`
- Produces: `init-admin` subcommand for each server role

- [ ] **Step 1: Add init-admin command for manufacturing**

In `cmd/manufacturing.go`, add after `manufacturingCmd` definition:

```go
var manufacturingInitAdminCmd = &cobra.Command{
	Use:   "init-admin",
	Short: "Create initial admin user and API key",
	Long:  `Creates an admin user with full permissions and generates an API key. The API key is printed to stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var mfgConfig config.ManufacturingServerConfig
		if err := viper.Unmarshal(&mfgConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}

		gormDB, err := mfgConfig.DB.GetDB()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}

		ctx := cmd.Context()

		if err := state.InitAuthDB(ctx, gormDB); err != nil {
			return fmt.Errorf("failed to initialize auth database: %w", err)
		}

		name, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")
		force, _ := cmd.Flags().GetBool("force")

		serverScopes := []string{
			"vouchers:read", "vouchers:write", "vouchers:delete", "vouchers:extend",
			"rvinfo:read", "rvinfo:write", "rvinfo:delete",
		}
		seedCfg := config.SeedConfig{
			Admin: &config.SeedAdminConfig{Name: name, Email: email},
		}
		apiKey, err := state.SeedAuth(ctx, gormDB, seedCfg, serverScopes, force)
		if err != nil {
			return err
		}

		fmt.Println(apiKey)
		return nil
	},
}
```

In `manufacturingCmdInit()`, add:

```go
manufacturingCmd.AddCommand(manufacturingInitAdminCmd)
manufacturingInitAdminCmd.Flags().String("name", "admin", "Admin user name")
manufacturingInitAdminCmd.Flags().String("email", "admin@example.com", "Admin user email")
manufacturingInitAdminCmd.Flags().Bool("force", false, "Create admin even if users exist")
```

- [ ] **Step 2: Add same command for owner and rendezvous**

Apply the same pattern to `cmd/owner.go` and `cmd/rendezvous.go`, adjusting the `serverScopes` list for each role.

Owner scopes: `vouchers:read`, `vouchers:write`, `vouchers:delete`, `vouchers:extend`, `device-ca:read`, `device-ca:write`, `device-ca:delete`, `rvto2addr:read`, `rvto2addr:write`, `rvto2addr:delete`, `devices:read`

Rendezvous scopes: `device-ca:read`, `device-ca:write`, `device-ca:delete`

- [ ] **Step 3: Run the command to verify it works**

Run: `cd /Users/mmartinv/devel/redhat/src/fdo/go-fdo-server && go build -o /tmp/go-fdo-server . && /tmp/go-fdo-server manufacturing init-admin --config configs/manufacturing.yaml --name admin --email admin@test.com`
Expected: Prints an API key starting with `fdo_`

- [ ] **Step 4: Commit**

```bash
git add cmd/manufacturing.go cmd/owner.go cmd/rendezvous.go
git commit -m "feat: add init-admin CLI command for all server roles"
```

---

### Task 10: Update Config File Templates

**Files:**
- Modify: `configs/manufacturing.yaml` — add commented `auth` section
- Modify: `configs/owner.yaml` — add commented `auth` section
- Modify: `configs/rendezvous.yaml` — add commented `auth` section

**Interfaces:**
- Consumes: nothing
- Produces: Config files with auth section documentation

- [ ] **Step 1: Add auth section to all config templates**

Append to each config file:

```yaml

# Authentication and authorization configuration.
# When enabled, management API endpoints require valid credentials.
# FDO protocol endpoints (/fdo/101/msg/*, /fdo/200/msg/*) are never affected.
#auth:
#  enabled: true
#  mechanisms:
#    api_key:
#      enabled: true
#  seed:
#    admin:
#      name: "admin"
#      email: "admin@example.com"
```

- [ ] **Step 2: Commit**

```bash
git add configs/
git commit -m "docs: add auth configuration examples to config templates"
```
