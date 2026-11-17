package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// fakeRDS serves fixed clusters, proxies and tags. Names and hosts are placeholders.
type fakeRDS struct {
	clusters    []rdstypes.DBCluster
	proxies     []rdstypes.DBProxy
	endpoints   []rdstypes.DBProxyEndpoint
	tags        map[string]map[string]string // ARN -> tags
	endpointErr error
}

func (f *fakeRDS) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{DBClusters: f.clusters}, nil
}

func (f *fakeRDS) DescribeDBSubnetGroups(context.Context, *rds.DescribeDBSubnetGroupsInput, ...func(*rds.Options)) (*rds.DescribeDBSubnetGroupsOutput, error) {
	return &rds.DescribeDBSubnetGroupsOutput{}, nil
}

func (f *fakeRDS) DescribeDBProxies(context.Context, *rds.DescribeDBProxiesInput, ...func(*rds.Options)) (*rds.DescribeDBProxiesOutput, error) {
	return &rds.DescribeDBProxiesOutput{DBProxies: f.proxies}, nil
}

func (f *fakeRDS) DescribeDBProxyEndpoints(context.Context, *rds.DescribeDBProxyEndpointsInput, ...func(*rds.Options)) (*rds.DescribeDBProxyEndpointsOutput, error) {
	if f.endpointErr != nil {
		return nil, f.endpointErr
	}
	return &rds.DescribeDBProxyEndpointsOutput{DBProxyEndpoints: f.endpoints}, nil
}

func (f *fakeRDS) ListTagsForResource(_ context.Context, in *rds.ListTagsForResourceInput, _ ...func(*rds.Options)) (*rds.ListTagsForResourceOutput, error) {
	var list []rdstypes.Tag
	for k, v := range f.tags[aws.ToString(in.ResourceName)] {
		list = append(list, rdstypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return &rds.ListTagsForResourceOutput{TagList: list}, nil
}

func newFakeRDS() *fakeRDS {
	return &fakeRDS{
		clusters: []rdstypes.DBCluster{
			{DBClusterIdentifier: aws.String("tagged-cluster"), DBClusterArn: aws.String("arn:cluster:tagged"), Endpoint: aws.String("tagged-cluster.example.internal"), Engine: aws.String("aurora-postgresql"), Port: aws.Int32(5432)},
			{DBClusterIdentifier: aws.String("plain-cluster"), DBClusterArn: aws.String("arn:cluster:plain"), Endpoint: aws.String("plain-cluster.example.internal"), Engine: aws.String("aurora-postgresql")},
		},
		proxies: []rdstypes.DBProxy{
			{DBProxyName: aws.String("example-proxy"), EngineFamily: aws.String("MYSQL")},
		},
		endpoints: []rdstypes.DBProxyEndpoint{
			{DBProxyEndpointName: aws.String("tagged-endpoint"), DBProxyEndpointArn: aws.String("arn:endpoint:tagged"), DBProxyName: aws.String("example-proxy"), Endpoint: aws.String("tagged-endpoint.example.internal"), VpcId: aws.String("vpc-a")},
			{DBProxyEndpointName: aws.String("plain-endpoint"), DBProxyEndpointArn: aws.String("arn:endpoint:plain"), DBProxyName: aws.String("example-proxy"), Endpoint: aws.String("plain-endpoint.example.internal")},
		},
		tags: map[string]map[string]string{
			"arn:cluster:tagged":  {"bifrost:iam-auth": "true", TailnetNameTag: "stg-example-pg"},
			"arn:endpoint:tagged": {TailnetNameTag: "stg-example-mysql"},
		},
	}
}

func TestDiscoverRDSTailnetTags(t *testing.T) {
	got, err := discoverRDS(context.Background(), newFakeRDS(), "000000000000", "example", "DeveloperAccess", "eu-west-2")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Resource{}
	for _, r := range got {
		byName[r.Name] = r
	}
	if len(got) != 3 {
		t.Fatalf("got %d resources, want 2 clusters and 1 tagged proxy endpoint: %+v", len(got), got)
	}

	if r := byName["tagged-cluster"]; r.TailnetName != "stg-example-pg" || !r.IAMAuthEnabled || r.ServiceType != "rds" {
		t.Errorf("tagged cluster = %+v, want TailnetName stg-example-pg, IAM auth, service rds", r)
	}
	if r := byName["plain-cluster"]; r.TailnetName != "" || r.IAMAuthEnabled {
		t.Errorf("untagged cluster = %+v, want no tailnet name and no IAM auth", r)
	}
	ep, ok := byName["tagged-endpoint"]
	if !ok {
		t.Fatal("tagged proxy endpoint missing")
	}
	want := Resource{AccountID: "000000000000", AccountName: "example", RoleName: "DeveloperAccess", Region: "eu-west-2",
		ServiceType: "rds-proxy", Name: "tagged-endpoint", Engine: "mysql", Port: 3306,
		Endpoint: "tagged-endpoint.example.internal", VpcID: "vpc-a", TailnetName: "stg-example-mysql"}
	if ep != want {
		t.Errorf("proxy endpoint = %+v, want %+v", ep, want)
	}
	if _, ok := byName["plain-endpoint"]; ok {
		t.Error("untagged proxy endpoint should be left out")
	}
}

func TestDiscoverRDSProxyErrorKeepsClusters(t *testing.T) {
	f := newFakeRDS()
	f.endpointErr = errors.New("AccessDenied")
	got, err := discoverRDS(context.Background(), f, "000000000000", "example", "DeveloperAccess", "eu-west-2")
	if err != nil {
		t.Fatalf("proxy endpoint error should not fail discovery: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d resources, want the 2 clusters", len(got))
	}
}
