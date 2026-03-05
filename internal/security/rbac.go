package security

import (
	"context"
	"fmt"
	"net/http"
)

// Role represents a user's permission level within Falcn.
type Role string

const (
	RoleViewer  Role = "viewer"  // read-only access to scan results
	RoleAnalyst Role = "analyst" // can trigger scans and manage findings
	RoleAdmin   Role = "admin"   // manage users, policies, integrations
	RoleOwner   Role = "owner"   // full control including billing and deletion
)

// roleRank maps roles to a numeric rank so we can check >= comparisons.
var roleRank = map[Role]int{
	RoleViewer:  1,
	RoleAnalyst: 2,
	RoleAdmin:   3,
	RoleOwner:   4,
}

// AtLeast returns true if r is at least as privileged as minimum.
func (r Role) AtLeast(minimum Role) bool {
	return roleRank[r] >= roleRank[minimum]
}

// String implements Stringer.
func (r Role) String() string { return string(r) }

// ParseRole converts a string to Role, defaulting to RoleViewer on unknown values.
func ParseRole(s string) Role {
	switch Role(s) {
	case RoleViewer, RoleAnalyst, RoleAdmin, RoleOwner:
		return Role(s)
	default:
		return RoleViewer
	}
}

// ─────────────────────────────────────────────────────────────────
// Permission definitions
// ─────────────────────────────────────────────────────────────────

// Permission enumerates every guarded action in the API.
type Permission string

const (
	PermScanRead       Permission = "scan:read"
	PermScanCreate     Permission = "scan:create"
	PermScanDelete     Permission = "scan:delete"
	PermVulnRead       Permission = "vuln:read"
	PermPolicyRead     Permission = "policy:read"
	PermPolicyWrite    Permission = "policy:write"
	PermUserRead       Permission = "user:read"
	PermUserWrite      Permission = "user:write"
	PermUserDelete     Permission = "user:delete"
	PermIntegRead      Permission = "integration:read"
	PermIntegWrite     Permission = "integration:write"
	PermAuditRead      Permission = "audit:read"
	PermBillingRead    Permission = "billing:read"
	PermBillingWrite   Permission = "billing:write"
	PermOrgDelete      Permission = "org:delete"
)

// rolePermissions maps each role to the set of permissions it grants.
// Higher roles inherit all permissions of lower roles.
var rolePermissions = map[Role][]Permission{
	RoleViewer: {
		PermScanRead,
		PermVulnRead,
		PermPolicyRead,
	},
	RoleAnalyst: {
		PermScanRead, PermScanCreate,
		PermVulnRead,
		PermPolicyRead,
		PermIntegRead,
	},
	RoleAdmin: {
		PermScanRead, PermScanCreate, PermScanDelete,
		PermVulnRead,
		PermPolicyRead, PermPolicyWrite,
		PermUserRead, PermUserWrite,
		PermIntegRead, PermIntegWrite,
		PermAuditRead,
		PermBillingRead,
	},
	RoleOwner: {
		PermScanRead, PermScanCreate, PermScanDelete,
		PermVulnRead,
		PermPolicyRead, PermPolicyWrite,
		PermUserRead, PermUserWrite, PermUserDelete,
		PermIntegRead, PermIntegWrite,
		PermAuditRead,
		PermBillingRead, PermBillingWrite,
		PermOrgDelete,
	},
}

// HasPermission returns true if role grants the requested permission.
func HasPermission(role Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────
// HTTP middleware
// ─────────────────────────────────────────────────────────────────

// RequireRole is a middleware that denies requests whose authenticated role
// is below the required minimum.
func RequireRole(minimum Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleStr, _ := r.Context().Value(ContextKeyRole).(string)
		role := ParseRole(roleStr)
		if !role.AtLeast(minimum) {
			http.Error(w,
				fmt.Sprintf(`{"error":"forbidden","required_role":"%s","your_role":"%s"}`, minimum, role),
				http.StatusForbidden,
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission is a middleware that enforces a specific permission.
func RequirePermission(perm Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleStr, _ := r.Context().Value(ContextKeyRole).(string)
		role := ParseRole(roleStr)
		if !HasPermission(role, perm) {
			http.Error(w,
				fmt.Sprintf(`{"error":"forbidden","required_permission":"%s"}`, perm),
				http.StatusForbidden,
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RoleFromContext extracts the Role from a request context.
func RoleFromContext(ctx context.Context) Role {
	s, _ := ctx.Value(ContextKeyRole).(string)
	return ParseRole(s)
}

// UserIDFromContext extracts the user ID from a request context.
func UserIDFromContext(ctx context.Context) string {
	s, _ := ctx.Value(ContextKeyUserID).(string)
	return s
}

// OrgIDFromContext extracts the org ID from a request context.
func OrgIDFromContext(ctx context.Context) string {
	s, _ := ctx.Value(ContextKeyOrgID).(string)
	return s
}
