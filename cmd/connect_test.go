package cmd

import (
	"strings"
	"testing"
)

func TestPreferTagged(t *testing.T) {
	relay := bastionChoice{InstanceID: "i-relay"}
	bastion := bastionChoice{InstanceID: "i-bastion", Tagged: true}

	got := preferTagged([]bastionChoice{relay, bastion})
	if len(got) != 1 || got[0].InstanceID != "i-bastion" {
		t.Errorf("preferTagged() = %v, want only i-bastion", got)
	}

	got = preferTagged([]bastionChoice{relay})
	if len(got) != 1 || got[0].InstanceID != "i-relay" {
		t.Errorf("preferTagged() = %v, want i-relay when none tagged", got)
	}
}

func TestSuperuserWarning(t *testing.T) {
	cases := []struct {
		accountID string
		group     string
	}{
		{"904233092296", "infra-aws-database-admins-stg"},
		{"733573666215", "infra-aws-database-admins-prd"},
		{"111111111111", "infra-aws-database-admins"},
	}
	for _, c := range cases {
		got := superuserWarning(c.accountID)
		if !strings.Contains(got, c.group+" Google group") {
			t.Errorf("superuserWarning(%q) = %q, want it to name %s", c.accountID, got, c.group)
		}
		if !strings.Contains(got, "/g/"+c.group+"/members") {
			t.Errorf("superuserWarning(%q) = %q, want the %s members link", c.accountID, got, c.group)
		}
	}
	if got := superuserWarning("733573666215"); !strings.Contains(got, "infra-aws-database-admins group also works") {
		t.Errorf("superuserWarning(prd) = %q, want the old group mentioned", got)
	}
	if got := superuserWarning("111111111111"); strings.Contains(got, "also works") {
		t.Errorf("superuserWarning(other) = %q, want no mention of a second group", got)
	}
}
