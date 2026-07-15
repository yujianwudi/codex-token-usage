package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultModelPriceURL       = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
	modelPriceUpdateRetryDelay = 5 * time.Minute
)

var modelPriceDiagnosticURLPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

type modelPriceUpdateState struct {
	Enabled        bool   `json:"enabled"`
	URL            string `json:"url"`
	Path           string `json:"path"`
	IntervalHours  int    `json:"interval_hours"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	LastCheckedAt  string `json:"last_checked_at,omitempty"`
	LastUpdatedAt  string `json:"last_updated_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	FileSizeBytes  int64  `json:"file_size_bytes,omitempty"`
	Entries        int    `json:"entries,omitempty"`
	LoadedPrices   int    `json:"loaded_prices,omitempty"`
}

type modelPriceUpdateManager struct {
	lifecycleMu sync.Mutex
	mu          sync.Mutex
	cfg         pluginConfig
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	updating    bool
	state       modelPriceUpdateState
}

func modelPriceFilePath() string {
	path := strings.TrimSpace(os.Getenv("CPA_MODEL_PRICE_FILE"))
	if path == "" {
		path = filepath.Join(pluginDataDirBestEffort(), "model_prices.json")
	}
	return path
}

func (m *modelPriceUpdateManager) configure(cfg pluginConfig) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopLocked()

	m.mu.Lock()
	m.cfg = cfg
	m.state.Enabled = cfg.ModelPriceAutoUpdateEnabled
	m.state.URL = modelPriceURLForDiagnostics(cfg.ModelPriceUpdateURL)
	m.state.Path = modelPriceFilePath()
	m.state.IntervalHours = cfg.ModelPriceUpdateIntervalHours
	m.state.TimeoutSeconds = cfg.ModelPriceUpdateTimeoutSeconds
	m.mu.Unlock()
	if !cfg.ModelPriceAutoUpdateEnabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.ctx = ctx
	m.cancel = cancel
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		m.loop(ctx, cfg)
	}()
}

func (m *modelPriceUpdateManager) stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopLocked()
}

// stopLocked cancels and joins every goroutine belonging to the active
// configuration. Callers must hold lifecycleMu so that a concurrent
// configure cannot install a new cancel function while the old generation is
// being stopped.
func (m *modelPriceUpdateManager) stopLocked() {
	m.mu.Lock()
	cancel := m.cancel
	if m.cancel != nil {
		m.cancel = nil
	}
	m.ctx = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

func (m *modelPriceUpdateManager) status() modelPriceUpdateState {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	path := modelPriceFilePath()
	if info, err := os.Stat(path); err == nil {
		state.FileSizeBytes = info.Size()
		if state.LastUpdatedAt == "" {
			state.LastUpdatedAt = info.ModTime().Format(time.RFC3339)
		}
		if state.Entries == 0 || state.LoadedPrices == 0 {
			if raw, err := os.ReadFile(path); err == nil {
				if entries, loaded, err := validateModelPrices(raw); err == nil {
					state.Entries = entries
					state.LoadedPrices = loaded
					m.mu.Lock()
					if m.state.Entries == 0 || m.state.LoadedPrices == 0 {
						m.state.Entries = entries
						m.state.LoadedPrices = loaded
					}
					m.mu.Unlock()
				}
			}
		}
	}
	return state
}

func (m *modelPriceUpdateManager) ensureFresh() {
	m.mu.Lock()
	cfg := m.cfg
	ctx := m.ctx
	lastCheckedAt := m.state.LastCheckedAt
	m.mu.Unlock()
	if !cfg.ModelPriceAutoUpdateEnabled || ctx == nil || ctx.Err() != nil {
		return
	}
	if modelPriceFileFresh(modelPriceFilePath(), time.Duration(cfg.ModelPriceUpdateIntervalHours)*time.Hour) {
		return
	}
	if checkedAt, err := time.Parse(time.RFC3339, lastCheckedAt); err == nil && time.Since(checkedAt) < modelPriceUpdateRetryDelay {
		return
	}
	m.startAsyncUpdate(ctx, cfg)
}

func (m *modelPriceUpdateManager) loop(ctx context.Context, cfg pluginConfig) {
	m.runUpdate(ctx, cfg)
	ticker := time.NewTicker(time.Duration(cfg.ModelPriceUpdateIntervalHours) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runUpdate(ctx, cfg)
		}
	}
}

func (m *modelPriceUpdateManager) runUpdate(ctx context.Context, cfg pluginConfig) {
	if !m.beginUpdate(ctx) {
		return
	}
	defer m.finishUpdate()
	m.update(ctx, cfg)
}

func (m *modelPriceUpdateManager) startAsyncUpdate(ctx context.Context, cfg pluginConfig) {
	m.mu.Lock()
	if m.updating || ctx == nil || ctx.Err() != nil || m.ctx != ctx {
		m.mu.Unlock()
		return
	}
	m.updating = true
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer m.finishUpdate()
		m.update(ctx, cfg)
	}()
}

func (m *modelPriceUpdateManager) beginUpdate(ctx context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updating || ctx == nil || ctx.Err() != nil {
		return false
	}
	m.updating = true
	return true
}

func (m *modelPriceUpdateManager) finishUpdate() {
	m.mu.Lock()
	m.updating = false
	m.mu.Unlock()
}

func (m *modelPriceUpdateManager) update(ctx context.Context, cfg pluginConfig) {
	if cfg.ModelPriceUpdateURL == "" {
		cfg.ModelPriceUpdateURL = defaultModelPriceURL
	}
	if modelPriceFileFresh(modelPriceFilePath(), time.Duration(cfg.ModelPriceUpdateIntervalHours)*time.Hour) {
		m.recordPriceUpdateCheck("", 0, 0, false)
		return
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.ModelPriceUpdateTimeoutSeconds)*time.Second)
	defer cancel()
	entries, loaded, size, err := downloadModelPrices(timeoutCtx, cfg.ModelPriceUpdateURL, modelPriceFilePath())
	if err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return
		}
		m.recordPriceUpdateCheck(err.Error(), 0, 0, false)
		return
	}
	m.recordPriceUpdateCheck("", entries, loaded, true)
	m.mu.Lock()
	m.state.FileSizeBytes = size
	m.mu.Unlock()
}

func (m *modelPriceUpdateManager) recordPriceUpdateCheck(message string, entries, loaded int, updated bool) {
	now := time.Now().Format(time.RFC3339)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.LastCheckedAt = now
	m.state.LastError = sanitizeTriggerError(sanitizeModelPriceDiagnosticText(message))
	if updated {
		m.state.LastUpdatedAt = now
		m.state.Entries = entries
		m.state.LoadedPrices = loaded
	}
}

func modelPriceFileFresh(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 0 {
		return false
	}
	return time.Since(info.ModTime()) < maxAge
}

func downloadModelPrices(ctx context.Context, url, path string) (int, int, int64, error) {
	target, err := validatePublicModelPriceURL(ctx, strings.TrimSpace(url))
	if err != nil {
		return 0, 0, 0, err
	}
	client := &http.Client{
		Transport: publicModelPriceTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many price update redirects")
			}
			_, err := validatePublicModelPriceURL(req.Context(), req.URL.String())
			return err
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, 0, 0, err
	}
	req.Header.Set("User-Agent", pluginID+"/"+pluginVersion)
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, 0, 0, fmt.Errorf("price update returned HTTP %d", resp.StatusCode)
	}
	const maxPriceBytes = 10 << 20
	if resp.ContentLength > maxPriceBytes {
		return 0, 0, 0, fmt.Errorf("price update exceeds %d bytes", maxPriceBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPriceBytes+1))
	if err != nil {
		return 0, 0, 0, err
	}
	if len(raw) > maxPriceBytes {
		return 0, 0, 0, fmt.Errorf("price update exceeds %d bytes", maxPriceBytes)
	}
	entries, loaded, err := validateModelPrices(raw)
	if err != nil {
		return 0, 0, 0, err
	}
	if loaded == 0 {
		return entries, loaded, 0, fmt.Errorf("price update contained no usable prices")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return entries, loaded, 0, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return entries, loaded, 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return entries, loaded, 0, err
	}
	return entries, loaded, int64(len(raw)), nil
}

func publicModelPriceTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A preflight DNS check alone is vulnerable to DNS rebinding because the
	// HTTP transport resolves the hostname again when it opens the socket. Dial
	// only addresses that are public at connection time. Disable environment
	// proxies as well: a proxy would resolve the destination outside this check.
	transport.Proxy = nil
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse price update address: %w", err)
		}
		addresses, err := resolvePublicModelPriceHost(ctx, host)
		if err != nil {
			return nil, err
		}
		var dialErr error
		for _, ip := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			dialErr = err
		}
		return nil, fmt.Errorf("connect to price update host: %w", dialErr)
	}
	return transport
}

func validatePublicModelPriceURL(ctx context.Context, raw string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("invalid price update URL")
	}
	if !strings.EqualFold(target.Scheme, "https") {
		return nil, errors.New("price update URL must use https")
	}
	if target.User != nil {
		return nil, errors.New("price update URL must not contain credentials")
	}
	host := strings.TrimSpace(target.Hostname())
	if host == "" {
		return nil, errors.New("price update URL requires a host")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return nil, errors.New("price update URL must not target localhost")
	}
	if _, err := resolvePublicModelPriceHost(ctx, host); err != nil {
		return nil, err
	}
	return target, nil
}

func modelPriceURLForDiagnostics(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	target, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	if !strings.EqualFold(target.Scheme, "http") && !strings.EqualFold(target.Scheme, "https") {
		return "<invalid URL>"
	}
	if target.Hostname() == "" {
		return "<invalid URL>"
	}
	target.Scheme = strings.ToLower(target.Scheme)
	target.Host = strings.ToLower(target.Host)
	// Paths can contain tenant identifiers, signed object names, or embedded
	// credentials just as readily as query strings. Diagnostics only need the
	// destination origin, never the requested object path.
	target.Path = ""
	target.RawPath = ""
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	target.RawFragment = ""
	target.User = nil
	return target.String()
}

func sanitizeModelPriceDiagnosticText(message string) string {
	return modelPriceDiagnosticURLPattern.ReplaceAllStringFunc(message, modelPriceURLForDiagnostics)
}

func resolvePublicModelPriceHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if !publicModelPriceIP(ip) {
			return nil, errors.New("price update URL must not target a private address")
		}
		return []net.IP{ip}, nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve price update host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("price update host resolved to no addresses")
	}
	public := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if !publicModelPriceIP(address.IP) {
			return nil, errors.New("price update host resolves to a private address")
		}
		public = append(public, address.IP)
	}
	return public, nil
}

func publicModelPriceIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	// Go's IsPrivate intentionally excludes several special-purpose ranges
	// which must not be reachable by an SSRF-sensitive downloader.
	for _, prefix := range modelPriceBlockedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var modelPriceBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func validateModelPrices(raw []byte) (int, int, error) {
	var entries map[string]map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return 0, 0, err
	}
	loaded := 0
	for _, entry := range entries {
		if _, ok := modelPriceFromJSON(entry); ok {
			loaded++
		}
	}
	return len(entries), loaded, nil
}
