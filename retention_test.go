package main

import (
	"context"
	"testing"
)

func TestExecDeleteBatchesDeletesAllMatchingRows(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider) VALUES (1, 'codex')`); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider) VALUES (100, 'codex')`); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := execDeleteBatches(context.Background(), db, `
DELETE FROM usage_events
WHERE id IN (
  SELECT id FROM usage_events WHERE requested_at < ? ORDER BY id LIMIT ?
)`, 50, 3)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 7 {
		t.Fatalf("deleted = %d, want 7", deleted)
	}
	var remaining int
	if err := db.QueryRow(`SELECT COUNT(*) FROM usage_events`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining = %d, want 2", remaining)
	}
}

func TestExecDeleteBatchesLimitedYieldsWithBacklog(t *testing.T) {
	s := newTestStore(t)
	db, _, err := s.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := db.Exec(`INSERT INTO usage_events (requested_at, provider) VALUES (1, 'codex')`); err != nil {
			t.Fatal(err)
		}
	}
	query := `
DELETE FROM usage_events
WHERE id IN (
  SELECT id FROM usage_events WHERE requested_at < ? ORDER BY id LIMIT ?
)`
	deleted, more, err := execDeleteBatchesLimited(context.Background(), db, query, 50, 3, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 6 || !more {
		t.Fatalf("first pass = deleted %d, more %v; want deleted 6 with backlog", deleted, more)
	}
	deleted, more, err = execDeleteBatchesLimited(context.Background(), db, query, 50, 3, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 4 || more {
		t.Fatalf("second pass = deleted %d, more %v; want deleted 4 with no backlog", deleted, more)
	}
}

func TestRetentionCanceledRunDoesNotRecordFalseFailure(t *testing.T) {
	s := newTestStore(t)
	previousStore := globalStore
	globalStore = s
	t.Cleanup(func() { globalStore = previousStore })

	r := &retentionCleaner{state: retentionState{LastRunAt: "previous", LastError: "previous error"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if more := r.run(ctx, normalizePluginConfig(defaultPluginConfig())); more {
		t.Fatal("canceled retention run reported pending catch-up work")
	}
	state := r.status()
	if state.LastRunAt != "previous" || state.LastError != "previous error" {
		t.Fatalf("canceled run overwrote retention status: %+v", state)
	}
}
