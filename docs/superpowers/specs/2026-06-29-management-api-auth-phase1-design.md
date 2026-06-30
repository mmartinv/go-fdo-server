# Management API Authentication & Authorization — Phase 1 Design

**Date:** 2026-06-29
**Phase:** 1 of 3 — Auth framework + API key mechanism
**Status:** Approved

## Overview

This design introduces authentication and authorization for the FDO server management API. The existing OpenAPI specs declare five security schemes (Basic, Bearer, API Key, OIDC, OAuth2) and all endpoints reference 401/403 responses, but no authentication enforcement exists in the implementation.

Phase 1 establishes the auth framework and implements the first mechanism (API key). The framework is designed to accommodate additional mechanisms in later phases.

### Phase Roadmap

- **Phase 1** (this document): Auth framework + API key mechanism + configuration + bootstrapping
- **Phase 2**: Management API endpoints (CRUD for users, groups, roles, API keys) + CLI bootstrapping
- **Phase 3**: Additional auth mechanisms (Bearer, Basic, OIDC, OAuth2, SAML)

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| First auth mechanism | API key | Simplest end-to-end, no external deps, validates full pipeline |
| Authorization model | RBAC + fine-grained scopes | Scopes map to OAuth2 claims later; principle of least privilege |
| Auth data storage | Same DB as server role data | Matches existing per-server isolation; external IdP handles centralized identity |
| Role names | Shared (`admin`, `operator`) | Each server has isolated DB; prefix adds no real disambiguation |
| Management endpoints | Same API surface | Avoids second HTTP server complexity; auth-protected anyway |
| Bootstrapping | Config-file seed + CLI command | Config for automated deployments, CLI for manual setups |
| Auth mechanisms | Multiple simultaneously | Standard pattern; enables migration and M2M + human coexistence |
| Scope source of truth | OpenAPI `x-required-scopes` | Single source of truth; no drift between spec and code |
| Architecture | Middleware chain (AuthN → AuthZ) | Guarantees no handler can skip auth; clean separation of concerns |

## Core Auth Framework Architecture

### Identity Model

Every authenticated request resolves to an `Identity` — a unified representation regardless of how the user authenticated:

```go
type Identity struct {
    Subject    string            // unique identifier (user ID, API key ID)
    Name       string            // human-readable name
    AuthMethod string            // "api-key", "bearer", "basic", "oidc", etc.
    Roles      []string          // e.g., ["admin"]
    Scopes     []string          // effective scopes, resolved from roles + direct grants
    Metadata   map[string]string // auth-method-specific data
}
```

This is the contract between AuthN and AuthZ. The AuthZ middleware never needs to know how the user authenticated, only what they're authorized to do.

### Authenticator Interface

Each auth mechanism implements this interface:

```go
type Authenticator interface {
    // Name returns the mechanism name (e.g., "api-key", "oidc")
    Name() string
    // Authenticate inspects the request and returns an Identity if credentials are valid (*Identity, nil).
    // Returns (nil, error) if credentials are present but invalid.
    // Returns (nil, nil) if this authenticator doesn't match the request (no relevant credentials present).
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
```

The semantic: `nil, nil` means "not my request, try the next authenticator"; `nil, error` means "credentials were present but invalid — stop and return 401".

### Middleware Chain

```
Request → BodySize → RateLimit → AuthN → AuthZ → OpenAPI Validation → Handler
```

**AuthN middleware** iterates over enabled authenticators in order:

1. For each authenticator, call `Authenticate(ctx, r)`
2. If it returns an identity → set on context, proceed to AuthZ
3. If it returns `nil, nil` → try next authenticator
4. If it returns `nil, error` → return 401 immediately
5. If all return `nil, nil` → return 401 (no valid credentials found)
6. Skip auth entirely for excluded paths (health, docs, FDO protocol endpoints)

**AuthZ middleware** checks the resolved identity's scopes against the route's required scopes:

1. Look up required scopes for `method + path pattern`
2. If the identity's effective scopes include all required scopes → proceed
3. Otherwise → return 403

## Scopes, Roles, and Database Models

### Scope Definitions Per Server Type

Scopes follow the pattern `resource:action`.

**Manufacturer server:**

| Scope | Description |
|---|---|
| `vouchers:read` | List/get vouchers |
| `vouchers:write` | Import vouchers |
| `vouchers:delete` | Delete vouchers |
| `vouchers:extend` | Extend voucher ownership |
| `rvinfo:read` | Read rendezvous info config |
| `rvinfo:write` | Create/update rendezvous info config |
| `rvinfo:delete` | Delete rendezvous info config |

**Owner server:**

| Scope | Description |
|---|---|
| `vouchers:read` | List/get vouchers |
| `vouchers:write` | Import/verify ownership vouchers |
| `vouchers:delete` | Delete vouchers |
| `vouchers:extend` | Extend voucher ownership |
| `device-ca:read` | List/get device CA certs |
| `device-ca:write` | Add device CA certs |
| `device-ca:delete` | Delete device CA certs |
| `rvto2addr:read` | Get RVTO2 addresses |
| `rvto2addr:write` | Set RVTO2 addresses |
| `rvto2addr:delete` | Delete RVTO2 addresses |
| `devices:read` | List devices and onboarding state |

**Rendezvous server:**

| Scope | Description |
|---|---|
| `device-ca:read` | List/get device CA certs |
| `device-ca:write` | Add device CA certs |
| `device-ca:delete` | Delete device CA certs |

### Default Roles

| Role | Scopes |
|---|---|
| `admin` | All scopes for the server type + `auth:manage` (Phase 2 user/key management) |
| `operator` | All `*:read` + all `*:write` + `vouchers:extend` scopes for the server type (can create/modify, cannot delete or manage auth) |

Roles are stored in the database, not hardcoded. These are seed defaults created on first startup. Admins can create custom roles with arbitrary scope combinations via the management API (Phase 2). Built-in roles have a `BuiltIn` flag that prevents deletion.

### Database Models

```
┌─────────────┐       ┌──────────────────┐       ┌─────────────┐
│    User     │──M:N──│   UserRole       │──M:1──│    Role     │
├─────────────┤       ├──────────────────┤       ├─────────────┤
│ ID (UUID)   │       │ UserID           │       │ ID (UUID)   │
│ Name        │       │ RoleID           │       │ Name        │
│ Email       │       └──────────────────┘       │ Description │
│ Active      │                                  │ BuiltIn     │
│ CreatedAt   │       ┌──────────────────┐       │ CreatedAt   │
│ UpdatedAt   │       │   RoleScope      │──M:1──│ UpdatedAt   │
└─────────────┘       ├──────────────────┤       └─────────────┘
                      │ RoleID           │
                      │ Scope            │
                      └──────────────────┘

┌──────────────────┐
│    APIKey        │
├──────────────────┤
│ ID (UUID)        │
│ Prefix (6 chars) │  ← visible identifier for logs/display
│ HashedKey        │  ← SHA-256 hash of the full key
│ Name             │  ← human label ("CI pipeline key")
│ UserID (FK)      │  ← owning user
│ Scopes           │  ← optional scope restriction (subset of user's scopes)
│ ExpiresAt        │  ← optional expiration
│ Active           │
│ LastUsedAt       │
│ CreatedAt        │
│ UpdatedAt        │
└──────────────────┘
```

- API keys belong to users — a user can have multiple API keys, each optionally restricted to a subset of the user's scopes
- The full API key is shown once at creation, then only the SHA-256 hash is stored
- The prefix (first 6 chars after `fdo_`) is stored in cleartext for identification in logs and management UI
- If an API key has explicit scopes, they are intersected with the user's role-derived scopes. If empty, the key inherits all the user's scopes
- No groups in Phase 1 — they add organizational convenience but no authorization capability that roles don't already provide. Can be added in Phase 2 if needed.

## API Key Authentication Mechanism

### Key Format

```
fdo_<random-32-bytes-base62-encoded>
```

Example: `fdo_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2`

- Prefix `fdo_` makes keys identifiable (grep-able in logs, scannable by secret detection tools)
- 32 bytes of cryptographic randomness (256 bits of entropy)
- Base62 encoding (alphanumeric, no special chars) avoids shell escaping issues
- First 6 characters after `fdo_` stored as the `Prefix` field for display/identification

### Storage and Validation

- On creation: generate the key, return the full key to the user once, store only `sha256(full_key)`
- On request: extract `X-API-Key` header → query by prefix (first 6 chars after `fdo_`) → `sha256(provided_key)` + constant-time comparison to verify
- SHA-256 is appropriate here because API keys have ~190 bits of cryptographic randomness, making them immune to offline dictionary attacks. bcrypt's intentional slowness would add 50-100ms per request and create a CPU-exhaustion DoS vector
- Prefix-based lookup avoids full-table scan — the prefix is a non-unique index (~56 billion combinations with 6 base62 chars)

### Scope Resolution Logic

```
User roles → expand to role scopes → union = user's full scope set
API key scopes (if set) → intersect with user's full scope set = effective scopes
API key scopes (if empty) → user's full scope set = effective scopes
```

An API key can never exceed the user's permissions, even if the user's roles change after key creation.

### Authentication Flow

1. Extract `X-API-Key` header — if absent, return `nil, nil` (try next authenticator)
2. Validate format (`fdo_` prefix, minimum 10 characters total — 4-char prefix + 6-char identifier minimum) — if invalid, log at DEBUG level and return `nil, error`
3. Extract prefix (6 chars after `fdo_`)
4. Query API key candidates by prefix where `APIKey.Active = true`
5. Compute `sha256(provided_key)` and constant-time compare against each candidate's `HashedKey`
6. If match found, verify `User.Active = true` for the key's owning user — if user is inactive, log at WARN level and return `nil, error`
7. Check expiration — if expired, log at DEBUG level and return `nil, error` (same error as invalid credentials to avoid leaking key validity)
8. Update `last_used_at` asynchronously (background goroutine with 5-second timeout via `context.WithTimeout`; tracked by `sync.WaitGroup` for graceful shutdown draining; failures are logged at WARN level but do not block authentication)
9. Resolve effective scopes and return `Identity`
10. If no match, log at DEBUG level and return `nil, error`

## OpenAPI Spec Changes and Scope Parsing

### Custom Extension: `x-required-scopes`

Each operation in the OpenAPI spec gets an `x-required-scopes` array declaring required scopes:

```yaml
paths:
  /vouchers:
    get:
      operationId: ListOwnershipVouchers
      x-required-scopes:
        - vouchers:read
    post:
      operationId: ImportOwnershipVouchers
      x-required-scopes:
        - vouchers:write
  /vouchers/{guid}:
    get:
      operationId: GetOwnershipVoucherByGuid
      x-required-scopes:
        - vouchers:read
    delete:
      operationId: DeleteOwnershipVoucher
      x-required-scopes:
        - vouchers:delete
  /vouchers/{guid}/extend:
    post:
      operationId: ExtendOwnershipVoucher
      x-required-scopes:
        - vouchers:extend
  /vouchers/verify-ownership:
    post:
      operationId: VerifyOwnership
      x-required-scopes:
        - vouchers:write
```

Operations with no `x-required-scopes` (like `/health`) are treated as public.

When an operation lists multiple scopes, ALL are required (AND logic). For example, `x-required-scopes: [vouchers:read, vouchers:write]` requires the identity to have both scopes.

### Scope Parsing at Startup

The project already merges per-resource OpenAPI specs into a combined spec for each server role. The scope parser hooks into the same loaded spec:

```go
func ParseRouteScopes(specJSON []byte) (map[string][]string, error)
```

This runs once at startup. The returned map is passed to the AuthZ middleware.

### Startup Validation

1. **Missing scopes warning**: Operation has `security` schemes but no `x-required-scopes` → log warning
2. **Unknown scopes error**: `x-required-scopes` references a scope not in any role definition → fail startup
3. **Unprotected endpoints info**: Log which endpoints have no `x-required-scopes`

### Files Requiring `x-required-scopes` Annotations

| File | Operations |
|---|---|
| `api/v2/voucher/openapi.yaml` | 6 operations |
| `api/v2/deviceca/openapi.yaml` | 4 operations |
| `api/v2/rvinfo/openapi.yaml` | 3 operations |
| `api/v2/rvto2addr/openapi.yaml` | 3 operations |
| `api/v2/device/openapi.yaml` | 1 operation |
| `api/v2/health/openapi.yaml` | 0 operations (public) |

## Configuration Schema

### Auth Configuration Block

Added to each server's YAML config under a new `auth` key:

```yaml
auth:
  # When false or omitted, all endpoints are accessible without authentication.
  # When true, at least one mechanism must be enabled.
  enabled: true

  # Additional paths excluded from authentication.
  # Health check, docs, OpenAPI spec, and FDO protocol endpoints are always excluded.
  # excluded_paths:
  #   - /custom/public/endpoint

  # Authentication mechanisms — multiple can be enabled simultaneously.
  mechanisms:
    api_key:
      enabled: true

    # Future mechanisms (Phase 3):
    # basic:
    #   enabled: true
    # bearer:
    #   enabled: true
    #   jwt_secret: "..."
    #   jwt_issuer: "..."
    # oidc:
    #   enabled: true
    #   issuer_url: "https://auth.example.com/realms/fdo"
    #   client_id: "fdo-owner"
    # oauth2:
    #   enabled: true
    #   token_introspection_url: "..."
    #   client_id: "..."
    #   client_secret: "..."

  # Bootstrap: seed an initial admin user + API key on first startup.
  # Ignored if any users already exist in the database.
  seed:
    admin:
      name: "admin"
      email: "admin@example.com"
      # Optional: pre-set API key for automated deployments.
      # If omitted, a random key is generated and logged at WARN level.
      # api_key: "fdo_..."
```

### Config Struct

```go
type AuthConfig struct {
    Enabled       bool              `mapstructure:"enabled"`
    ExcludedPaths []string          `mapstructure:"excluded_paths"`
    Mechanisms    MechanismsConfig  `mapstructure:"mechanisms"`
    Seed          *SeedConfig       `mapstructure:"seed"`
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
```

### Validation Rules

- `auth.enabled: true` requires at least one mechanism enabled — otherwise startup fails
- `auth.enabled: false` or omitted → auth middleware not installed, backward-compatible
- `seed.admin` processed only when auth is enabled AND no users exist in the database
- Pre-set `seed.admin.api_key` validated for format (`fdo_` prefix, minimum length)
- Generated API key logged at `WARN` level with message to save it

### CLI Bootstrap Command

```
go-fdo-server <role> init-admin --name "admin" --email "admin@example.com"
```

- Creates admin user with `admin` role and generates an API key
- Prints the API key to stdout
- Fails if users already exist (use `--force` to create additional admin)
- Uses the same config file for DB connection (`--config` flag)

## Package Layout

```
internal/
├── auth/                          # Core auth framework
│   ├── identity.go                # Identity type, context helpers
│   ├── authenticator.go           # Authenticator interface
│   ├── middleware.go              # AuthN and AuthZ middleware
│   ├── scopes.go                  # Scope parser (OpenAPI x-required-scopes)
│   └── apikey/                    # API key authenticator
│       ├── authenticator.go       # APIKeyAuthenticator implementation
│       └── keygen.go              # Key generation, hashing, validation
├── config/
│   ├── auth.go                    # AuthConfig structs + validation (NEW)
│   └── server.go                  # Updated: add Auth field to ServerConfig
├── state/
│   ├── user.go                    # User GORM model + DB operations (NEW)
│   ├── role.go                    # Role, RoleScope GORM models + DB operations (NEW)
│   ├── apikey.go                  # APIKey GORM model + DB operations (NEW)
│   └── seed.go                    # Bootstrap seeding logic (NEW)
├── server/
│   ├── manufacturing.go           # Updated: wire auth middleware
│   ├── owner.go                   # Updated: wire auth middleware
│   └── rendezvous.go              # Updated: wire auth middleware
```

### Server Startup Sequence (Updated)

1. Load config (existing)
2. Initialize DB (existing)
3. Auto-migrate auth tables (NEW)
4. Seed admin if needed (NEW)
5. Parse route scopes from OpenAPI spec (NEW)
6. Build authenticator chain from config (NEW)
7. Create handler with middleware chain (MODIFIED — insert AuthN + AuthZ)
8. Start HTTP server (existing)

### Middleware Chain Assembly

```go
// Before:
handler = bodySize(rateLimit(openapiValidation(mux)))

// After:
handler = bodySize(rateLimit(authN(authZ(openapiValidation(mux)))))
```

### Dependencies

- `crypto/sha256` + `crypto/subtle` (standard library) — API key hashing and constant-time comparison
- No external auth frameworks

## Backward Compatibility

### Zero-Breaking-Change Guarantee

Default behavior when `auth` is not configured is identical to current behavior — all endpoints are open:

- Existing deployments continue working without config changes
- Existing integration tests pass without modification
- FDO protocol endpoints are never affected by management API auth

### Migration Path

1. **Upgrade binary** — No config changes needed. Auth tables auto-migrated (empty). Auth middleware not installed.
2. **Enable auth** — Add `auth` section to config. On restart: seed admin created, API key logged, auth middleware installed.
3. **Distribute keys** — Admin uses seeded key to create additional users/keys via CLI (Phase 1) or management API (Phase 2).

### FDO Protocol Endpoint Exclusion

Always excluded from management API auth (hardcoded):

```
/fdo/101/msg/*        # FDO v1.1 protocol messages
/fdo/200/msg/*        # FDO v2.0 protocol messages
/health               # Health check
/api/docs/*           # Swagger UI
/api/openapi.json     # OpenAPI spec
```

The `auth.excluded_paths` config option allows adding custom exclusions on top of these defaults.

**Path matching semantics:** Excluded paths use exact match for leaf paths (e.g., `/health` matches only `/health`, not `/health-check` or `/healthy`). Paths ending with `/` are treated as prefix matches (e.g., `/api/docs/` matches `/api/docs/index.html`). This prevents unintended authentication bypasses through path manipulation.

### V1 API Protection

The legacy V1 management API (`/api/v1/`) supports voucher and rendezvous info operations. When auth is enabled, V1 endpoints MUST also be wrapped with the authentication middleware to prevent bypass. The V1 endpoints share the same auth middleware chain as V2 — authenticators and scope definitions are identical. V1 endpoints map to the same scopes as their V2 equivalents.

### Database Migration

Auth tables added via GORM `AutoMigrate` — same pattern as existing models. New tables only, no modifications to existing tables, safe to run repeatedly.

## Future Considerations: API Key Lifecycle

### Expired Key Cleanup

Phase 1 does not clean up expired API keys — they remain in the database but are rejected during authentication. Over time, expired keys accumulate as dead rows. Phase 2 should provide a cleanup mechanism:

- A management API endpoint (e.g., `DELETE /api/v2/apikeys?expired=true`) for admin-initiated cleanup
- Optionally, a periodic background job that deletes keys expired beyond a configurable retention period (e.g., 30 days)

### Batched `last_used_at` Updates

If authentication throughput becomes a concern, the per-request `UpdateAPIKeyLastUsed` goroutine can be replaced with a batching pattern: collect key IDs in a channel and flush to the database in bulk every N seconds. Not needed for Phase 1 given expected load.

## Future Considerations: Multi-Tenancy on the Manufacturer Server

This section documents a planned evolution of the authorization model that goes beyond Phase 1. It is captured here to confirm that the Phase 1 framework does not block this path.

### Use Case

The manufacturer server allows multiple customers (device owners) to register accounts. Each customer:

- Registers their own owner public keys via a management API
- Can self-register (public registration endpoint)
- Can view only the vouchers that were extended to their keys
- Cannot see other customers' vouchers or keys

The manufacturer admin retains full access to all resources and can use any registered owner key to extend vouchers at sell time.

### New Role: `customer`

| Role | Scopes | Resource access |
|---|---|---|
| `admin` | All scopes + `auth:manage` | All resources (no ownership filter) |
| `operator` | `*:read` + `*:write` + `vouchers:extend` | All resources |
| `customer` | `vouchers:read`, `owner-keys:read`, `owner-keys:write` | Only own resources |

The key difference: `customer` and `admin` may share the same scope (`vouchers:read`) but the effective query is different — admin sees all, customer sees only theirs. This is **resource-level authorization** handled at the handler level using the `Identity.Subject` (user ID) from the request context, not in the scope middleware.

### What Changes Are Required

None of these require changes to the Phase 1 auth framework:

1. **New `OwnerKey` database model** — stores customer-uploaded owner public keys with a `UserID` foreign key
2. **New management API endpoints** — CRUD for owner keys, self-registration
3. **`OwnerID` foreign key on Voucher** — tracks which customer's key was used to extend each voucher
4. **Handler-level ownership filtering** — voucher list/get handlers check the identity's role; if `customer`, filter by `owner_id = identity.Subject`
5. **New `customer` role** — database insert with appropriate scopes

### Why Phase 1 Already Supports This

- The `Identity` struct carries `Subject` (user ID) and `Roles` — handlers can use these for resource filtering
- Adding a `customer` role is a database insert, not a code change
- New scopes (`owner-keys:read`, `owner-keys:write`) just need `x-required-scopes` on new endpoints
- The `Authenticator` interface and middleware chain are unaffected
- The scope intersection logic on API keys works identically for customer-scoped keys
