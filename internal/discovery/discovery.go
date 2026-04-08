package discovery

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"golang.org/x/sync/errgroup"
)

const preferredRole = "DeveloperAccess"

// Discover scans all accessible accounts in parallel and returns the combined
// list of RDS and Redis resources, each annotated with a bastion instance.
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
	cfg, err := buildAWSConfig(ctx, ssoRegion, token, accountID, roleName, region)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}

	// Discover resources in parallel within this account
	var (
		rdsResources   []Resource
		redisResources []Resource
		bastionID      string
		bastionName    string
	)

	ig, ictx := errgroup.WithContext(ctx)

	ig.Go(func() error {
		r, err := discoverRDS(ictx, cfg, accountID, accountName, roleName, region)
		if err != nil {
			log.Printf("Warning: RDS discovery failed for %s: %v", accountName, err)
			return nil
		}
		rdsResources = r
		return nil
	})

	ig.Go(func() error {
		r, err := discoverRedis(ictx, cfg, accountID, accountName, roleName, region)
		if err != nil {
			log.Printf("Warning: Redis discovery failed for %s: %v", accountName, err)
			return nil
		}
		redisResources = r
		return nil
	})

	ig.Go(func() error {
		id, name, err := discoverBastion(ictx, cfg)
		if err != nil {
			log.Printf("Warning: bastion discovery failed for %s: %v", accountName, err)
			return nil
		}
		bastionID = id
		bastionName = name
		return nil
	})

	if err := ig.Wait(); err != nil {
		return nil, err
	}

	// Attach bastion to all resources in this account
	var results []Resource
	for _, r := range append(rdsResources, redisResources...) {
		r.BastionID = bastionID
		r.BastionName = bastionName
		results = append(results, r)
	}
	return results, nil
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

func buildAWSConfig(ctx context.Context, ssoRegion string, token *ssooidc.CreateTokenOutput, accountID, roleName, region string) (aws.Config, error) {
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

func discoverRDS(ctx context.Context, cfg aws.Config, accountID, accountName, roleName, region string) ([]Resource, error) {
	client := rds.NewFromConfig(cfg)
	out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, db := range out.DBInstances {
		if db.DBInstanceIdentifier == nil || db.Endpoint == nil {
			continue
		}

		// Check for bifrost:iam-auth tag
		iamAuth := false
		tags, err := client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
			ResourceName: db.DBInstanceArn,
		})
		if err == nil {
			for _, tag := range tags.TagList {
				if *tag.Key == "bifrost:iam-auth" && *tag.Value == "true" {
					iamAuth = true
					break
				}
			}
		}

		engine := "unknown"
		if db.Engine != nil {
			engine = *db.Engine
		}

		resources = append(resources, Resource{
			AccountID:      accountID,
			AccountName:    accountName,
			RoleName:       roleName,
			Region:         region,
			ServiceType:    "rds",
			Name:           *db.DBInstanceIdentifier,
			Engine:         engine,
			Port:           *db.Endpoint.Port,
			Endpoint:       *db.Endpoint.Address,
			IAMAuthEnabled: iamAuth,
		})
	}
	return resources, nil
}

func discoverRedis(ctx context.Context, cfg aws.Config, accountID, accountName, roleName, region string) ([]Resource, error) {
	client := elasticache.NewFromConfig(cfg)
	out, err := client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, err
	}

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
		})
	}
	return resources, nil
}

func discoverBastion(ctx context.Context, cfg aws.Config) (string, string, error) {
	ssmClient := ssm.NewFromConfig(cfg)
	out, err := ssmClient.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return "", "", err
	}

	// Find first online instance
	var instanceID string
	for _, inst := range out.InstanceInformationList {
		if inst.PingStatus == ssmtypes.PingStatusOnline && inst.InstanceId != nil {
			instanceID = *inst.InstanceId
			break
		}
	}
	if instanceID == "" {
		return "", "", nil // no bastion found, not an error
	}

	// Get Name tag
	ec2Client := ec2.NewFromConfig(cfg)
	desc, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return instanceID, "", nil // return ID without name
	}

	var name string
	for _, res := range desc.Reservations {
		for _, inst := range res.Instances {
			for _, tag := range inst.Tags {
				if *tag.Key == "Name" {
					name = *tag.Value
				}
			}
		}
	}
	return instanceID, name, nil
}
