package discovery

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"golang.org/x/sync/errgroup"
)

const preferredRole = "DeveloperAccess"

// Discover scans all accessible accounts in parallel and returns the combined
// list of RDS clusters, tagged RDS Proxy endpoints and Redis resources, each
// annotated with a bastion instance.
func Discover(
	ctx context.Context,
	ssoRegion string,
	token *ssooidc.CreateTokenOutput,
	accounts []ssotypes.AccountInfo,
	region string,
) ([]Resource, error) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5) // avoid SSO rate limits

	var mu sync.Mutex
	var all []Resource

	for _, acct := range accounts {
		acct := acct
		g.Go(func() error {
			resources, err := discoverAccount(ctx, ssoRegion, token, acct, region)
			if err != nil {
				log.Printf("Warning: skipping account %s (%s): %v", *acct.AccountName, *acct.AccountId, err)
				return nil // don't fail the whole discovery
			}
			mu.Lock()
			all = append(all, resources...)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return all, nil
}

func discoverAccount(
	ctx context.Context,
	ssoRegion string,
	token *ssooidc.CreateTokenOutput,
	account ssotypes.AccountInfo,
	region string,
) ([]Resource, error) {
	accountID := *account.AccountId
	accountName := *account.AccountName

	// Select role
	roleName, err := selectRole(ctx, ssoRegion, token, accountID)
	if err != nil {
		return nil, fmt.Errorf("no usable role: %w", err)
	}

	// Get credentials
	cfg, err := BuildAWSConfig(ctx, ssoRegion, token, accountID, roleName, region)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}

	// Discover resources in parallel within this account
	var (
		rdsResources   []Resource
		redisResources []Resource
		bastions       []bastionInfo
	)

	ig, ictx := errgroup.WithContext(ctx)

	ig.Go(func() error {
		r, err := discoverRDS(ictx, rds.NewFromConfig(cfg), accountID, accountName, roleName, region)
		if err != nil {
			return fmt.Errorf("RDS discovery failed for %s: %w", accountName, err)
		}
		rdsResources = r
		return nil
	})

	ig.Go(func() error {
		r, err := discoverRedis(ictx, cfg, accountID, accountName, roleName, region)
		if err != nil {
			return fmt.Errorf("redis discovery failed for %s: %w", accountName, err)
		}
		redisResources = r
		return nil
	})

	ig.Go(func() error {
		b, err := discoverBastions(ictx, cfg)
		if err != nil {
			return fmt.Errorf("bastion discovery failed for %s: %w", accountName, err)
		}
		bastions = b
		return nil
	})

	if err := ig.Wait(); err != nil {
		return nil, err
	}

	// Attach a bastion that lives in the same VPC as each resource. Accounts can
	// host multiple VPCs (e.g. dev/staging/prod), so a single account-wide bastion
	// would route connections through the wrong network. If no same-VPC bastion is
	// found, leave BastionID empty; the connect flow resolves/validates it again
	// against the resource's VPC and errors rather than using a wrong-VPC host.
	var results []Resource
	for _, r := range append(rdsResources, redisResources...) {
		r.BastionID = matchBastion(bastions, r.VpcID)
		results = append(results, r)
	}
	return results, nil
}

// bastionInfo is a candidate bastion host annotated with the VPC it sits in.
type bastionInfo struct {
	InstanceID string
	VpcID      string
	Tagged     bool // carries bifrost:bastion=true
}

// BastionTag marks an EC2 instance as a bastion host. In a VPC where any
// SSM-managed instance carries bifrost:bastion=true, only tagged instances are
// candidates; elsewhere every SSM-managed instance is, so untagged accounts keep
// working. Other SSM-managed hosts (e.g. the Datastream relays) share the
// bastions' VPCs but cannot reach every database.
const BastionTag = "bifrost:bastion"

// IsBastionTagged reports whether tags include bifrost:bastion=true.
func IsBastionTagged(tags []ec2types.Tag) bool {
	for _, tag := range tags {
		if tag.Key != nil && *tag.Key == BastionTag && tag.Value != nil && *tag.Value == "true" {
			return true
		}
	}
	return false
}

// matchBastion returns the first tagged bastion in the given VPC, else the first
// bastion in it, or "" if none match.
func matchBastion(bastions []bastionInfo, vpcID string) string {
	if vpcID == "" {
		return ""
	}
	first := ""
	for _, b := range bastions {
		if b.VpcID != vpcID {
			continue
		}
		if b.Tagged {
			return b.InstanceID
		}
		if first == "" {
			first = b.InstanceID
		}
	}
	return first
}

func selectRole(ctx context.Context, ssoRegion string, token *ssooidc.CreateTokenOutput, accountID string) (string, error) {
	ssoClient := sso.NewFromConfig(aws.Config{Region: ssoRegion})
	out, err := ssoClient.ListAccountRoles(ctx, &sso.ListAccountRolesInput{
		AccountId:   aws.String(accountID),
		AccessToken: token.AccessToken,
	})
	if err != nil {
		return "", err
	}
	if len(out.RoleList) == 0 {
		return "", fmt.Errorf("no roles available")
	}
	// Prefer DeveloperAccess
	for _, role := range out.RoleList {
		if *role.RoleName == preferredRole {
			return preferredRole, nil
		}
	}
	// Fall back to first available
	return *out.RoleList[0].RoleName, nil
}

// BuildAWSConfig creates an aws.Config using SSO role credentials for the given account.
func BuildAWSConfig(ctx context.Context, ssoRegion string, token *ssooidc.CreateTokenOutput, accountID, roleName, region string) (aws.Config, error) {
	ssoClient := sso.NewFromConfig(aws.Config{Region: ssoRegion})
	creds, err := ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: token.AccessToken,
		AccountId:   aws.String(accountID),
		RoleName:    aws.String(roleName),
	})
	if err != nil {
		return aws.Config{}, err
	}

	return awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			*creds.RoleCredentials.AccessKeyId,
			*creds.RoleCredentials.SecretAccessKey,
			*creds.RoleCredentials.SessionToken,
		)),
	)
}

// rdsAPI is the subset of the RDS client discovery uses, so tests can fake it.
type rdsAPI interface {
	DescribeDBClusters(ctx context.Context, in *rds.DescribeDBClustersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBSubnetGroups(ctx context.Context, in *rds.DescribeDBSubnetGroupsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSubnetGroupsOutput, error)
	DescribeDBProxies(ctx context.Context, in *rds.DescribeDBProxiesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBProxiesOutput, error)
	DescribeDBProxyEndpoints(ctx context.Context, in *rds.DescribeDBProxyEndpointsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBProxyEndpointsOutput, error)
	ListTagsForResource(ctx context.Context, in *rds.ListTagsForResourceInput, optFns ...func(*rds.Options)) (*rds.ListTagsForResourceOutput, error)
}

// TailnetNameTag names the tailnet host a database is served on, e.g.
// bifrost:tailnet-name=stg-example-pg. Infra sets it; `bifrost tailscale` reads it.
const TailnetNameTag = "bifrost:tailnet-name"

// rdsTags returns the resource's tags as a map, or an empty map if they cannot be read.
func rdsTags(ctx context.Context, client rdsAPI, arn *string) map[string]string {
	m := map[string]string{}
	if arn == nil {
		return m
	}
	out, err := client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: arn})
	if err != nil {
		return m
	}
	for _, tag := range out.TagList {
		if tag.Key != nil && tag.Value != nil {
			m[*tag.Key] = *tag.Value
		}
	}
	return m
}

func discoverRDS(ctx context.Context, client rdsAPI, accountID, accountName, roleName, region string) ([]Resource, error) {
	out, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, err
	}

	// Map DB subnet group name -> VPC so each cluster can be matched to a bastion.
	subnetVPCs := rdsSubnetGroupVPCs(ctx, client)

	var resources []Resource
	for _, cluster := range out.DBClusters {
		if cluster.DBClusterIdentifier == nil || cluster.Endpoint == nil {
			continue
		}

		var vpcID string
		if cluster.DBSubnetGroup != nil {
			vpcID = subnetVPCs[*cluster.DBSubnetGroup]
		}

		tags := rdsTags(ctx, client, cluster.DBClusterArn)

		engine := "unknown"
		if cluster.Engine != nil {
			engine = *cluster.Engine
		}

		var port int32 = 5432
		if cluster.Port != nil {
			port = *cluster.Port
		}

		resources = append(resources, Resource{
			AccountID:      accountID,
			AccountName:    accountName,
			RoleName:       roleName,
			Region:         region,
			ServiceType:    "rds",
			Name:           *cluster.DBClusterIdentifier,
			Engine:         engine,
			Port:           port,
			Endpoint:       *cluster.Endpoint,
			VpcID:          vpcID,
			IAMAuthEnabled: tags["bifrost:iam-auth"] == "true",
			TailnetName:    tags[TailnetNameTag],
		})
	}

	resources = append(resources, discoverTailnetProxyEndpoints(ctx, client, accountID, accountName, roleName, region)...)
	return resources, nil
}

// discoverTailnetProxyEndpoints returns the RDS Proxy endpoints that carry
// bifrost:tailnet-name. Untagged endpoints are left out: `bifrost connect` does
// not tunnel to proxies. Errors yield none rather than dropping the account's
// clusters, since not every role may describe proxies.
func discoverTailnetProxyEndpoints(ctx context.Context, client rdsAPI, accountID, accountName, roleName, region string) []Resource {
	out, err := client.DescribeDBProxyEndpoints(ctx, &rds.DescribeDBProxyEndpointsInput{})
	if err != nil || len(out.DBProxyEndpoints) == 0 {
		return nil
	}

	// Endpoints don't carry an engine; their proxy's engine family does.
	families := map[string]string{}
	if proxies, err := client.DescribeDBProxies(ctx, &rds.DescribeDBProxiesInput{}); err == nil {
		for _, p := range proxies.DBProxies {
			if p.DBProxyName != nil && p.EngineFamily != nil {
				families[*p.DBProxyName] = strings.ToLower(*p.EngineFamily)
			}
		}
	}

	var resources []Resource
	for _, ep := range out.DBProxyEndpoints {
		if ep.DBProxyEndpointName == nil || ep.Endpoint == nil {
			continue
		}
		name := rdsTags(ctx, client, ep.DBProxyEndpointArn)[TailnetNameTag]
		if name == "" {
			continue
		}

		engine := "unknown"
		if ep.DBProxyName != nil && families[*ep.DBProxyName] != "" {
			engine = families[*ep.DBProxyName]
		}
		// Proxy endpoints listen on the engine family's default port.
		var port int32 = 5432
		if engine == "mysql" {
			port = 3306
		}

		resources = append(resources, Resource{
			AccountID:   accountID,
			AccountName: accountName,
			RoleName:    roleName,
			Region:      region,
			ServiceType: "rds-proxy",
			Name:        *ep.DBProxyEndpointName,
			Engine:      engine,
			Port:        port,
			Endpoint:    *ep.Endpoint,
			VpcID:       aws.ToString(ep.VpcId),
			TailnetName: name,
		})
	}
	return resources
}

func discoverRedis(ctx context.Context, cfg aws.Config, accountID, accountName, roleName, region string) ([]Resource, error) {
	client := elasticache.NewFromConfig(cfg)
	out, err := client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, err
	}

	// ElastiCache replication groups don't carry a VPC directly; resolve it via a
	// member cache cluster's subnet group. Build both maps once for the account.
	clusterSubnet := cacheClusterSubnetGroups(ctx, client) // cache cluster id -> subnet group name
	subnetVPCs := cacheSubnetGroupVPCs(ctx, client)        // subnet group name -> VPC

	var resources []Resource
	for _, rg := range out.ReplicationGroups {
		if rg.ReplicationGroupId == nil {
			continue
		}

		var endpoint string
		var port int32 = 6379
		if len(rg.NodeGroups) > 0 && rg.NodeGroups[0].PrimaryEndpoint != nil {
			endpoint = *rg.NodeGroups[0].PrimaryEndpoint.Address
			port = *rg.NodeGroups[0].PrimaryEndpoint.Port
		}

		var vpcID string
		if len(rg.MemberClusters) > 0 {
			vpcID = subnetVPCs[clusterSubnet[rg.MemberClusters[0]]]
		}

		resources = append(resources, Resource{
			AccountID:   accountID,
			AccountName: accountName,
			RoleName:    roleName,
			Region:      region,
			ServiceType: "redis",
			Name:        *rg.ReplicationGroupId,
			Engine:      "redis",
			Port:        port,
			Endpoint:    endpoint,
			VpcID:       vpcID,
		})
	}
	return resources, nil
}

// discoverBastions returns the online SSM-managed instances in the account, each
// annotated with the VPC it sits in so resources can be matched to a same-VPC host.
func discoverBastions(ctx context.Context, cfg aws.Config) ([]bastionInfo, error) {
	ssmClient := ssm.NewFromConfig(cfg)
	out, err := ssmClient.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, inst := range out.InstanceInformationList {
		if inst.PingStatus == ssmtypes.PingStatusOnline && inst.InstanceId != nil {
			ids = append(ids, *inst.InstanceId)
		}
	}
	if len(ids) == 0 {
		return nil, nil // no bastion found, not an error
	}

	// Resolve each instance's VPC via EC2.
	ec2Client := ec2.NewFromConfig(cfg)
	desc, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: ids})
	if err != nil {
		// Without VPC data we can't safely match; return ids with empty VPCs so the
		// connect flow falls back to prompting rather than auto-picking wrongly.
		bastions := make([]bastionInfo, 0, len(ids))
		for _, id := range ids {
			bastions = append(bastions, bastionInfo{InstanceID: id})
		}
		return bastions, nil
	}

	var bastions []bastionInfo
	for _, res := range desc.Reservations {
		for _, inst := range res.Instances {
			if inst.InstanceId == nil {
				continue
			}
			var vpcID string
			if inst.VpcId != nil {
				vpcID = *inst.VpcId
			}
			bastions = append(bastions, bastionInfo{InstanceID: *inst.InstanceId, VpcID: vpcID, Tagged: IsBastionTagged(inst.Tags)})
		}
	}
	return bastions, nil
}

// rdsSubnetGroupVPCs maps DB subnet group name -> VPC ID for the account/region.
func rdsSubnetGroupVPCs(ctx context.Context, client rdsAPI) map[string]string {
	m := map[string]string{}
	out, err := client.DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{})
	if err != nil {
		return m
	}
	for _, sg := range out.DBSubnetGroups {
		if sg.DBSubnetGroupName != nil && sg.VpcId != nil {
			m[*sg.DBSubnetGroupName] = *sg.VpcId
		}
	}
	return m
}

// cacheClusterSubnetGroups maps cache cluster id -> cache subnet group name.
func cacheClusterSubnetGroups(ctx context.Context, client *elasticache.Client) map[string]string {
	m := map[string]string{}
	out, err := client.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
	if err != nil {
		return m
	}
	for _, cc := range out.CacheClusters {
		if cc.CacheClusterId != nil && cc.CacheSubnetGroupName != nil {
			m[*cc.CacheClusterId] = *cc.CacheSubnetGroupName
		}
	}
	return m
}

// cacheSubnetGroupVPCs maps cache subnet group name -> VPC ID for the account/region.
func cacheSubnetGroupVPCs(ctx context.Context, client *elasticache.Client) map[string]string {
	m := map[string]string{}
	out, err := client.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{})
	if err != nil {
		return m
	}
	for _, sg := range out.CacheSubnetGroups {
		if sg.CacheSubnetGroupName != nil && sg.VpcId != nil {
			m[*sg.CacheSubnetGroupName] = *sg.VpcId
		}
	}
	return m
}
