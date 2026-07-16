package main

import "errors"

var errNoRows = errors.New("no rows")

const schemaSQL = `
CREATE TABLE IF NOT EXISTS usage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requested_at INTEGER NOT NULL,
  provider TEXT NOT NULL CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  executor_type TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  alias TEXT NOT NULL DEFAULT '',
  api_key TEXT NOT NULL DEFAULT '',
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  auth_type TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  reasoning_effort TEXT NOT NULL DEFAULT '',
  service_tier TEXT NOT NULL DEFAULT '',
  generate INTEGER NOT NULL DEFAULT 1,
	latency_ms INTEGER NOT NULL DEFAULT 0,
	ttft_ms INTEGER NOT NULL DEFAULT 0,
	failed INTEGER NOT NULL DEFAULT 0,
	status_code INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  reasoning_tokens INTEGER NOT NULL DEFAULT 0,
  cached_tokens INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens INTEGER NOT NULL DEFAULT 0,
  cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  primary_used_percent REAL,
  primary_reset_at INTEGER,
  secondary_used_percent REAL,
  secondary_reset_at INTEGER,
  primary_used_tokens INTEGER,
  primary_remaining_tokens INTEGER,
  primary_limit_tokens INTEGER,
  secondary_used_tokens INTEGER,
  secondary_remaining_tokens INTEGER,
  secondary_limit_tokens INTEGER
);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_at ON usage_events(requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_auth ON usage_events(auth_index, auth_id, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_model ON usage_events(model, alias, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_auth_id ON usage_events(requested_at, auth_id);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_source ON usage_events(requested_at, source);
CREATE INDEX IF NOT EXISTS idx_usage_events_quota_scan ON usage_events(requested_at, failed, status_code);
CREATE INDEX IF NOT EXISTS idx_usage_events_api_key_requested ON usage_events(api_key, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_provider_requested ON usage_events(provider, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_status_requested ON usage_events(status_code, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_requested_id_desc ON usage_events(requested_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_lower_auth_index_requested ON usage_events(lower(auth_index), requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_lower_auth_id_requested ON usage_events(lower(auth_id), requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_lower_source_requested ON usage_events(lower(source), requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_provider_model_requested ON usage_events(provider, model, alias, requested_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_api_key_provider_requested ON usage_events(api_key, provider, requested_at);
CREATE TABLE IF NOT EXISTS account_protection_reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  auth_file TEXT NOT NULL DEFAULT '',
  plan_type TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_protection_reservations_expiry ON account_protection_reservations(expires_at);
CREATE INDEX IF NOT EXISTS idx_account_protection_reservations_auth ON account_protection_reservations(provider, auth_index, auth_id, source, expires_at);
CREATE TABLE IF NOT EXISTS xai_account_states (
  state_key TEXT NOT NULL,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'xai' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  state TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  observed_at INTEGER NOT NULL,
  reset_at INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 0,
  auth_file TEXT NOT NULL DEFAULT '',
  auth_file_mtime INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (provider, state_key)
);
CREATE INDEX IF NOT EXISTS idx_xai_account_states_active_reset ON xai_account_states(provider, active, reset_at);
CREATE INDEX IF NOT EXISTS idx_xai_account_states_auth ON xai_account_states(provider, auth_index, auth_id, source);
CREATE TABLE IF NOT EXISTS summary_cache (
  cache_key TEXT PRIMARY KEY,
  window TEXT NOT NULL DEFAULT '',
  limit_count INTEGER NOT NULL DEFAULT 0,
  cached_at INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  revision TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  data_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_summary_cache_cached_at ON summary_cache(cached_at);
CREATE TABLE IF NOT EXISTS store_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS autoban_bans (
  auth_id TEXT NOT NULL,
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  window TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  banned_at INTEGER NOT NULL,
  reset_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 429,
  primary_used_percent REAL,
  primary_reset_at INTEGER,
  secondary_used_percent REAL,
  secondary_reset_at INTEGER,
  released_at INTEGER NOT NULL DEFAULT 0,
  release_reason TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (provider, auth_id)
);
CREATE INDEX IF NOT EXISTS idx_autoban_bans_active_reset ON autoban_bans(provider, active, reset_at);
CREATE TABLE IF NOT EXISTS invalid_auths (
  auth_id TEXT NOT NULL,
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  reason TEXT NOT NULL DEFAULT '',
  invalidated_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_status_code INTEGER NOT NULL DEFAULT 401,
  auth_file TEXT NOT NULL DEFAULT '',
  auth_file_mtime INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (provider, auth_id)
);
CREATE INDEX IF NOT EXISTS idx_invalid_auths_active ON invalid_auths(provider, active);
CREATE TABLE IF NOT EXISTS quota_trigger_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id TEXT NOT NULL DEFAULT '',
  auth_index TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider <> '' AND provider = trim(provider) AND provider = lower(provider)),
  auth_file TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  http_status INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  finished_at INTEGER NOT NULL,
  primary_used_percent REAL,
  primary_reset_at INTEGER,
  secondary_used_percent REAL,
  secondary_reset_at INTEGER,
  primary_used_tokens INTEGER,
  primary_remaining_tokens INTEGER,
  primary_limit_tokens INTEGER,
  secondary_used_tokens INTEGER,
  secondary_remaining_tokens INTEGER,
  secondary_limit_tokens INTEGER
);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_account ON quota_trigger_runs(provider, auth_index, auth_id, source, auth_file, finished_at);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_finished_at ON quota_trigger_runs(finished_at);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_status_finished ON quota_trigger_runs(status, finished_at);
CREATE INDEX IF NOT EXISTS idx_quota_trigger_runs_auth_file_finished ON quota_trigger_runs(auth_file, finished_at);
INSERT OR IGNORE INTO store_state(key,value) VALUES
  ('scheduler_revision_codex','0'),
  ('scheduler_revision_xai','0'),
  ('scheduler_revision_privacy','0');
CREATE TRIGGER IF NOT EXISTS trg_invalid_auths_revision_insert
AFTER INSERT ON invalid_auths WHEN NEW.provider='codex'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_codex','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_invalid_auths_revision_update
AFTER UPDATE ON invalid_auths WHEN OLD.provider='codex' OR NEW.provider='codex'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_codex','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_invalid_auths_revision_delete
AFTER DELETE ON invalid_auths WHEN OLD.provider='codex'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_codex','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_autoban_bans_revision_insert
AFTER INSERT ON autoban_bans WHEN NEW.provider='codex'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_codex','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_autoban_bans_revision_update
AFTER UPDATE ON autoban_bans WHEN OLD.provider='codex' OR NEW.provider='codex'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_codex','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_autoban_bans_revision_delete
AFTER DELETE ON autoban_bans WHEN OLD.provider='codex'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_codex','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_xai_account_states_revision_insert
AFTER INSERT ON xai_account_states WHEN NEW.provider='xai'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_xai','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_xai_account_states_revision_update
AFTER UPDATE ON xai_account_states WHEN OLD.provider='xai' OR NEW.provider='xai'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_xai','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_xai_account_states_revision_delete
AFTER DELETE ON xai_account_states WHEN OLD.provider='xai'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_xai','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_privacy_quarantine_revision_insert
AFTER INSERT ON store_state WHEN NEW.key GLOB 'api_key_privacy_quarantine_*'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_privacy','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_privacy_quarantine_revision_update
AFTER UPDATE ON store_state WHEN OLD.key GLOB 'api_key_privacy_quarantine_*' OR NEW.key GLOB 'api_key_privacy_quarantine_*'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_privacy','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
CREATE TRIGGER IF NOT EXISTS trg_privacy_quarantine_revision_delete
AFTER DELETE ON store_state WHEN OLD.key GLOB 'api_key_privacy_quarantine_*'
BEGIN
  INSERT INTO store_state(key,value) VALUES('scheduler_revision_privacy','1')
  ON CONFLICT(key) DO UPDATE SET value=CAST(store_state.value AS INTEGER)+1;
END;
`

const insertSQL = `
INSERT INTO usage_events (
  requested_at, provider, executor_type, model, alias, api_key, auth_id, auth_index, auth_type, source,
  reasoning_effort, service_tier, generate, latency_ms, ttft_ms, failed, status_code, input_tokens, output_tokens, reasoning_tokens,
  cached_tokens, cache_read_tokens, cache_creation_tokens, total_tokens,
  primary_used_percent, primary_reset_at, secondary_used_percent, secondary_reset_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
