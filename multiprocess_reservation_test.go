package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	reservationWorkerEnv     = "CTU_RESERVATION_WORKER"
	reservationLockHolderEnv = "CTU_RESERVATION_LOCK_HOLDER"
	reservationResultPrefix  = "CTU_RESERVATION_RESULT "
)

type reservationWorkerCommand struct {
	Phase string `json:"phase"`
	Round int    `json:"round"`
}

type reservationWorkerResult struct {
	Phase      string `json:"phase"`
	Round      int    `json:"round"`
	Outcome    string `json:"outcome,omitempty"`
	DurationUS int64  `json:"duration_us,omitempty"`
}

// TestReservationWorkerProcess is an external-process harness entrypoint. The
// parent test keeps workers alive and uses a two-phase pipe barrier so each
// round competes on the same SQLite capacity snapshot.
func TestReservationWorkerProcess(t *testing.T) {
	if os.Getenv(reservationWorkerEnv) != "1" {
		return
	}
	limit, err := strconv.Atoi(os.Getenv("CTU_RESERVATION_LIMIT"))
	if err != nil || limit <= 0 {
		t.Fatalf("invalid worker limit: %q", os.Getenv("CTU_RESERVATION_LIMIT"))
	}
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = limit
	cfg.AccountProtectionPlusConcurrency = limit
	cfg.AccountProtectionReservationTTLSeconds = 30
	candidateCount, err := strconv.Atoi(os.Getenv("CTU_RESERVATION_CANDIDATES"))
	if err != nil || candidateCount <= 0 {
		t.Fatalf("invalid worker candidate count: %q", os.Getenv("CTU_RESERVATION_CANDIDATES"))
	}
	plan := "free"
	if limit > 1 {
		plan = "plus"
	}
	candidates := make([]schedulerAuthCandidate, candidateCount)
	for i := range candidates {
		candidates[i] = schedulerAuthCandidate{
			ID:       fmt.Sprintf("shared-free-account-%03d", i),
			Provider: providerCodex,
			Priority: 1,
			Status:   "active",
			Attributes: map[string]string{
				"auth_index": "shared-free-account",
				"auth_file":  "shared-free-account.json",
				"plan_type":  plan,
			},
		}
	}
	globalAccountProtection.configure(cfg)
	t.Cleanup(globalAccountProtection.stop)
	s := &store{}
	t.Cleanup(s.close)

	scanner := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	var pending int
	for scanner.Scan() {
		var command reservationWorkerCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			t.Fatalf("decode command: %v", err)
		}
		switch command.Phase {
		case "prepare":
			pending = command.Round
			writeReservationWorkerResult(t, writer, reservationWorkerResult{Phase: "ready", Round: pending})
		case "go":
			if command.Round != pending {
				t.Fatalf("go round %d without prepare %d", command.Round, pending)
			}
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
			resp, err := s.pickAuthOnce(ctx, schedulerPickRequest{
				Provider:   "codex",
				Model:      "multiprocess-hard-limit",
				Candidates: candidates,
				Options: schedulerOptions{Headers: map[string][]string{
					"Session-Id": {"multiprocess-affinity"},
				}},
			})
			cancel()
			outcome := "success"
			if err != nil {
				outcome = "unavailable"
				var reject *schedulerRejectError
				if errors.As(err, &reject) && reject.Code == "account_protection_saturated" {
					outcome = "saturated"
				}
			} else if !resp.Handled {
				outcome = "unavailable"
			}
			writeReservationWorkerResult(t, writer, reservationWorkerResult{
				Phase:      "result",
				Round:      command.Round,
				Outcome:    outcome,
				DurationUS: time.Since(started).Microseconds(),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("worker stdin: %v", err)
	}
}

func writeReservationWorkerResult(t *testing.T, writer *bufio.Writer, result reservationWorkerResult) {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(writer, reservationResultPrefix+string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestReservationLockHolderProcess(t *testing.T) {
	if os.Getenv(reservationLockHolderEnv) != "1" {
		return
	}
	path, err := usageDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db, err := openSQLiteReservationDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	fmt.Fprintln(os.Stdout, reservationResultPrefix+`{"phase":"locked"}`)
	_ = os.Stdout.Sync()
	select {}
}

type reservationWorkerClient struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	results <-chan reservationWorkerResult
	done    <-chan error
}

func startReservationWorker(t *testing.T, dataDir string, limit, candidateCount int) reservationWorkerClient {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestReservationWorkerProcess$", "-test.v=false")
	command.Env = append(os.Environ(),
		reservationWorkerEnv+"=1",
		"CTU_RESERVATION_LIMIT="+strconv.Itoa(limit),
		"CTU_RESERVATION_CANDIDATES="+strconv.Itoa(candidateCount),
		"CPA_TOKEN_USAGE_DIR="+dataDir,
		"CPA_CONFIG_PATH="+filepath.Join(dataDir, "missing-config.yaml"),
	)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	results := make(chan reservationWorkerResult, 4)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, reservationResultPrefix) {
				continue
			}
			var result reservationWorkerResult
			if json.Unmarshal([]byte(strings.TrimPrefix(line, reservationResultPrefix)), &result) == nil {
				results <- result
			}
		}
		close(results)
	}()
	go func() { done <- command.Wait() }()
	return reservationWorkerClient{command: command, stdin: stdin, results: results, done: done}
}

func sendReservationWorkerCommand(t *testing.T, worker reservationWorkerClient, command reservationWorkerCommand) {
	t.Helper()
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.stdin.Write(append(raw, '\n')); err != nil {
		t.Fatalf("send worker command: %v", err)
	}
}

func awaitReservationWorkerResult(t *testing.T, worker reservationWorkerClient, phase string, round int) reservationWorkerResult {
	t.Helper()
	select {
	case result, ok := <-worker.results:
		if !ok {
			t.Fatal("reservation worker exited before result")
		}
		if result.Phase != phase || result.Round != round {
			t.Fatalf("worker result=%+v, want phase=%s round=%d", result, phase, round)
		}
		return result
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for worker phase=%s round=%d", phase, round)
		return reservationWorkerResult{}
	}
}

func stopReservationWorkers(t *testing.T, workers []reservationWorkerClient) {
	t.Helper()
	for _, worker := range workers {
		_ = worker.stdin.Close()
	}
	for _, worker := range workers {
		select {
		case err := <-worker.done:
			if err != nil {
				t.Errorf("reservation worker exit: %v", err)
			}
		case <-time.After(3 * time.Second):
			_ = worker.command.Process.Kill()
			t.Errorf("reservation worker did not exit")
		}
	}
}

func TestAccountProtectionMultiprocessHardLimit(t *testing.T) {
	if os.Getenv(reservationWorkerEnv) == "1" || os.Getenv(reservationLockHolderEnv) == "1" {
		return
	}
	rounds := 20
	if os.Getenv("CPA_MULTIPROCESS_STRESS") == "1" {
		rounds = 1000
	}
	scenarios := []struct {
		processes  int
		limit      int
		candidates int
	}{
		{processes: 2, limit: 1, candidates: 10},
		{processes: 4, limit: 1, candidates: 10},
		{processes: 4, limit: 2, candidates: 10},
		{processes: 8, limit: 1, candidates: 100},
		{processes: 8, limit: 3, candidates: 100},
	}
	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(fmt.Sprintf("processes_%d_limit_%d_candidates_%d", scenario.processes, scenario.limit, scenario.candidates), func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("CPA_TOKEN_USAGE_DIR", dataDir)
			t.Setenv("CPA_CONFIG_PATH", filepath.Join(dataDir, "missing-config.yaml"))
			path := filepath.Join(dataDir, "usage.db")
			db, err := openSQLiteDB(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
				t.Fatal(err)
			}

			workers := make([]reservationWorkerClient, scenario.processes)
			for i := range workers {
				workers[i] = startReservationWorker(t, dataDir, scenario.limit, scenario.candidates)
			}
			defer stopReservationWorkers(t, workers)

			maxSuccess := 0
			busy := 0
			var latencies []int64
			for round := 1; round <= rounds; round++ {
				if _, err := db.Exec(`DELETE FROM account_protection_reservations WHERE provider=?`, providerCodex); err != nil {
					t.Fatal(err)
				}
				if round == 1 {
					now := time.Now().Unix()
					if _, err := db.Exec(`
INSERT INTO account_protection_reservations
  (provider, auth_id, auth_index, source, auth_file, plan_type, created_at, expires_at)
VALUES (?, 'expired', 'shared-free-account', '', '', 'free', ?, ?)`, providerCodex, now-60, now-1); err != nil {
						t.Fatal(err)
					}
				}
				for _, worker := range workers {
					sendReservationWorkerCommand(t, worker, reservationWorkerCommand{Phase: "prepare", Round: round})
				}
				for _, worker := range workers {
					awaitReservationWorkerResult(t, worker, "ready", round)
				}
				for _, worker := range workers {
					sendReservationWorkerCommand(t, worker, reservationWorkerCommand{Phase: "go", Round: round})
				}
				successes := 0
				saturated := 0
				for _, worker := range workers {
					result := awaitReservationWorkerResult(t, worker, "result", round)
					latencies = append(latencies, result.DurationUS)
					switch result.Outcome {
					case "success":
						successes++
					case "saturated":
						saturated++
					default:
						busy++
					}
				}
				if successes > maxSuccess {
					maxSuccess = successes
				}
				if successes != scenario.limit || saturated != scenario.processes-scenario.limit {
					t.Fatalf("round=%d successes=%d saturated=%d unavailable=%d", round, successes, saturated, scenario.processes-successes-saturated)
				}
			}
			p50 := percentileMicroseconds(latencies, 50)
			p95 := percentileMicroseconds(latencies, 95)
			p99 := percentileMicroseconds(latencies, 99)
			t.Logf("processes=%d rounds=%d limit=%d candidates=%d max_successes=%d busy=%d p50=%dus p95=%dus p99=%dus", scenario.processes, rounds, scenario.limit, scenario.candidates, maxSuccess, busy, p50, p95, p99)
			if maxSuccess != scenario.limit || busy != 0 {
				t.Fatalf("max_successes=%d busy=%d, want %d and 0", maxSuccess, busy, scenario.limit)
			}
			if p99 >= 700_000 {
				t.Fatalf("p99=%dus exceeds 700ms safety budget", p99)
			}
		})
	}
}

func percentileMicroseconds(values []int64, percentile int) int64 {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]int64(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*percentile + 99) / 100
	if index <= 0 {
		index = 1
	}
	return ordered[index-1]
}

func TestReservationWriterCrashRecovery(t *testing.T) {
	if os.Getenv(reservationWorkerEnv) == "1" || os.Getenv(reservationLockHolderEnv) == "1" {
		return
	}
	dataDir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dataDir)
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(dataDir, "missing-config.yaml"))
	path := filepath.Join(dataDir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(os.Args[0], "-test.run=^TestReservationLockHolderProcess$", "-test.v=false")
	command.Env = append(os.Environ(),
		reservationLockHolderEnv+"=1",
		"CPA_TOKEN_USAGE_DIR="+dataDir,
		"CPA_CONFIG_PATH="+filepath.Join(dataDir, "missing-config.yaml"),
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	locked := make(chan struct{})
	go func() {
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), `"phase":"locked"`) {
				close(locked)
				return
			}
		}
	}()
	select {
	case <-locked:
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("lock holder did not acquire BEGIN IMMEDIATE")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()

	db, err = openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	problems, err := sqliteQuickCheckProblems(context.Background(), db, 5)
	if err != nil || !sqliteIntegrityOK(problems) {
		t.Fatalf("quick_check after killed writer: problems=%v err=%v", problems, err)
	}
	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	previousCfg := globalAccountProtection.config()
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })
	s := &store{db: db, dbPath: path}
	defer s.close()
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	_, err = s.pickProtectedAuth(ctx, db, []schedulerAuthCandidate{{
		ID: "crash-recovery", Provider: providerCodex, Status: "active",
		Attributes: map[string]string{"auth_index": "crash-recovery", "plan_type": "free"},
	}}, cfg, "crash-recovery")
	if err != nil {
		t.Fatalf("pick after killed writer: %v", err)
	}
}

func TestReservationWriterLockFailsClosedWithinSchedulerBudget(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("CPA_TOKEN_USAGE_DIR", dataDir)
	t.Setenv("CPA_CONFIG_PATH", filepath.Join(dataDir, "missing-config.yaml"))
	path := filepath.Join(dataDir, "usage.db")
	db, err := openSQLiteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeSQLiteStore(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	locker, err := openSQLiteReservationDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	lockTx, err := locker.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lockTx.Rollback()

	cfg := defaultPluginConfig()
	cfg.AccountProtectionEnabled = true
	cfg.AccountProtectionFreeConcurrency = 1
	previousCfg := globalAccountProtection.config()
	globalAccountProtection.configure(cfg)
	t.Cleanup(func() { globalAccountProtection.configure(previousCfg) })
	s := &store{db: db, dbPath: path}
	defer s.close()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = s.pickProtectedAuth(ctx, db, []schedulerAuthCandidate{{
		ID: "locked", Provider: providerCodex, Status: "active",
		Attributes: map[string]string{"auth_index": "locked", "plan_type": "free"},
	}}, cfg, "writer-lock")
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("writer lock failed open and dispatched a protected candidate")
	}
	var reject *schedulerRejectError
	if errors.As(err, &reject) && reject.Code == "account_protection_saturated" {
		t.Fatalf("writer lock was misreported as saturated: %v", err)
	}
	if !isSQLiteBusyError(err) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want a temporary scheduler database failure", err)
	}
	if elapsed >= 650*time.Millisecond {
		t.Fatalf("writer lock elapsed=%v, want at least 100ms safety margin below the 750ms scheduler deadline", elapsed)
	}
	var reservations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_protection_reservations WHERE provider=?`, providerCodex).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 {
		t.Fatalf("writer-lock failure created %d reservations", reservations)
	}
}
