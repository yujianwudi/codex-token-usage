package main

import "testing"

func TestSchedulerRotationUsesStableIdentityForDuplicateIDs(t *testing.T) {
	var rotation schedulerRotationManager
	a := schedulerAuthCandidate{
		ID:       "shared",
		Provider: "codex",
		Priority: 1,
		Attributes: map[string]string{
			"auth_file": "a.json",
		},
	}
	b := schedulerAuthCandidate{
		ID:       "shared",
		Provider: "codex",
		Priority: 1,
		Attributes: map[string]string{
			"auth_file": "b.json",
		},
	}

	if got := rotation.pick("codex\x00model", []schedulerAuthCandidate{b, a}); got.Attributes["auth_file"] != "a.json" {
		t.Fatalf("first pick auth file = %q, want a.json", got.Attributes["auth_file"])
	}
	if got := rotation.pick("codex\x00model", []schedulerAuthCandidate{a, b}); got.Attributes["auth_file"] != "b.json" {
		t.Fatalf("second pick auth file = %q, want b.json", got.Attributes["auth_file"])
	}
	if got := rotation.pick("codex\x00model", []schedulerAuthCandidate{b, a}); got.Attributes["auth_file"] != "a.json" {
		t.Fatalf("third pick auth file = %q, want a.json", got.Attributes["auth_file"])
	}
}
