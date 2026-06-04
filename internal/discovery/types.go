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
	VpcID       string `json:"vpc_id"`   // VPC the resource lives in; used to pick a same-VPC bastion

	IAMAuthEnabled bool `json:"iam_auth_enabled"` // true if bifrost:iam-auth=true tag present

	BastionID string `json:"bastion_id"`
}

// Cache is the on-disk JSON envelope for discovered resources.
type Cache struct {
	Version   int        `json:"version"`
	CachedAt  time.Time  `json:"cached_at"`
	Resources []Resource `json:"resources"`
}

const CacheTTL = 1 * time.Hour

// CacheVersion is bumped whenever the cached Resource shape changes in a way that
// makes older caches unsafe to reuse. v2 added per-resource VPC + VPC-matched
// bastion selection; pre-v2 caches must be discarded so they re-discover.
const CacheVersion = 2
