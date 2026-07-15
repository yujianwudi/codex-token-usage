package main

import (
	"fmt"
	"testing"
	"time"
)

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

func TestSchedulerRotationCursorMapIsBounded(t *testing.T) {
	var rotation schedulerRotationManager
	candidates := []schedulerAuthCandidate{{ID: "only", Provider: "codex"}}
	for i := 0; i < schedulerRotationMaxCursors+200; i++ {
		rotation.pick(fmt.Sprintf("codex\x00model-%d", i), candidates)
	}
	if got := len(rotation.cursors); got > schedulerRotationMaxCursors {
		t.Fatalf("cursor count = %d, max = %d", got, schedulerRotationMaxCursors)
	}
}

func TestSchedulerRotationPrunesExpiredCursors(t *testing.T) {
	now := time.Now()
	rotation := schedulerRotationManager{
		cursors: map[string]schedulerRotationCursor{
			"stale": {next: 10, lastUsed: now.Add(-schedulerRotationCursorTTL - time.Minute).UnixNano()},
			"live":  {next: 5, lastUsed: now.UnixNano()},
		},
		operations: 255,
	}
	rotation.pick("live", []schedulerAuthCandidate{{ID: "only", Provider: "codex"}})
	if _, ok := rotation.cursors["stale"]; ok {
		t.Fatal("expired rotation cursor was not pruned")
	}
	if _, ok := rotation.cursors["live"]; !ok {
		t.Fatal("live rotation cursor was pruned")
	}
}
