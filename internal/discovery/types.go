package discovery

import "time"

// Resource represents a single connectable resource discovered across AWS accounts.
type Resource struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	RoleName    string `json:"role_name"`
	Region      string `json:"region"`

	ServiceType string `json:"service_type"` // "rds" or "redis"
	Name        string `json:"name"`         // DB instance identifier or replication group ID
	Engine      string `json:"engine"`       // "aurora-postgresql", "aurora-mysql", "redis", etc.
	Port        int32  `json:"port"`
	Endpoint    string `json:"endpoint"` // full hostname

	IAMAuthEnabled bool `json:"iam_auth_enabled"` // true if bifrost:iam-auth=true tag present

	BastionID   string `json:"bastion_id"`
	BastionName string `json:"bastion_name"`
}

// DisplayName returns a human-readable label like "staging-shared (aurora-postgresql:5432)".
func (r Resource) DisplayName() string {
	return r.Name + " (" + r.Engine + ")"
}

// Cache is the on-disk JSON envelope for discovered resources.
type Cache struct {
	SSOProfile string     `json:"sso_profile"`
	CachedAt   time.Time  `json:"cached_at"`
	Resources  []Resource `json:"resources"`
}

const CacheTTL = 1 * time.Hour
