package discovery

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestMatchBastion(t *testing.T) {
	relay := bastionInfo{InstanceID: "i-relay", VpcID: "vpc-a"}
	bastion := bastionInfo{InstanceID: "i-bastion", VpcID: "vpc-a", Tagged: true}
	other := bastionInfo{InstanceID: "i-other", VpcID: "vpc-b", Tagged: true}

	tests := []struct {
		name     string
		bastions []bastionInfo
		vpcID    string
		want     string
	}{
		{"tagged wins over earlier untagged", []bastionInfo{relay, bastion}, "vpc-a", "i-bastion"},
		{"untagged when none tagged", []bastionInfo{relay}, "vpc-a", "i-relay"},
		{"tagged in another VPC ignored", []bastionInfo{relay, other}, "vpc-a", "i-relay"},
		{"no instance in VPC", []bastionInfo{other}, "vpc-a", ""},
		{"unknown VPC", []bastionInfo{bastion}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchBastion(tt.bastions, tt.vpcID); got != tt.want {
				t.Errorf("matchBastion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsBastionTagged(t *testing.T) {
	tag := func(k, v string) ec2types.Tag { return ec2types.Tag{Key: aws.String(k), Value: aws.String(v)} }
	if !IsBastionTagged([]ec2types.Tag{tag("Name", "x"), tag(BastionTag, "true")}) {
		t.Error("want tagged for bifrost:bastion=true")
	}
	if IsBastionTagged([]ec2types.Tag{tag(BastionTag, "false")}) {
		t.Error("want untagged for bifrost:bastion=false")
	}
	if IsBastionTagged(nil) {
		t.Error("want untagged for no tags")
	}
}
