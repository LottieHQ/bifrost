package cmd

import "testing"

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
