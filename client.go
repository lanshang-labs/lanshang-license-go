package license

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ServerURL    string
	Product      string
	Organization string
	Key          string
	InstanceID   string
	PublicKeys   map[string]ed25519.PublicKey
	CachePath    string
	// AllowHTTP is for loopback tests and development only.
	AllowHTTP  bool
	HTTPClient *http.Client
}

type Status struct {
	State       string    `json:"state"`
	Valid       bool      `json:"valid"`
	Claims      *Claims   `json:"claims,omitempty"`
	LastChecked time.Time `json:"last_checked,omitempty"`
}

type cache struct {
	Fingerprint string    `json:"fingerprint"`
	Lease       *Lease    `json:"lease,omitempty"`
	Denial      string    `json:"denial,omitempty"`
	Checked     time.Time `json:"checked"`
}

type Client struct {
	mu          sync.Mutex
	refreshMu   sync.Mutex
	cfg         Config
	http        *http.Client
	cached      cache
	nextAttempt time.Time
	now         func() time.Time
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Scheme != "https" && !(cfg.AllowHTTP && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return nil, errors.New("invalid license server URL")
	}
	if cfg.Product == "" || cfg.Organization == "" || cfg.Key == "" || cfg.InstanceID == "" || len(cfg.PublicKeys) == 0 {
		return nil, errors.New("incomplete license configuration")
	}
	keys := make(map[string]ed25519.PublicKey, len(cfg.PublicKeys))
	for id, key := range cfg.PublicKeys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid trust root")
		}
		keys[id] = append(ed25519.PublicKey{}, key...)
	}
	cfg.PublicKeys = keys
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	hc := &http.Client{Timeout: 10 * time.Second}
	if cfg.HTTPClient != nil {
		*hc = *cfg.HTTPClient
	}
	if hc.Timeout <= 0 || hc.Timeout > 30*time.Second {
		hc.Timeout = 10 * time.Second
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("license redirects disabled") }
	c := &Client{cfg: cfg, http: hc, now: time.Now}
	sum := sha256.Sum256([]byte(cfg.ServerURL + "\x00" + cfg.Product + "\x00" + cfg.Organization + "\x00" + cfg.Key + "\x00" + cfg.InstanceID))
	c.cached.Fingerprint = hex.EncodeToString(sum[:])
	if cfg.CachePath != "" {
		f, err := os.Open(cfg.CachePath)
		if err != nil && !os.IsNotExist(err) {
			return nil, errors.New("cannot read license cache")
		}
		if err == nil {
			defer f.Close()
			raw, err := io.ReadAll(io.LimitReader(f, 32769))
			var saved cache
			if err == nil && len(raw) <= 32768 && json.Unmarshal(raw, &saved) == nil && saved.Fingerprint == c.cached.Fingerprint {
				c.cached = saved
			}
		}
	}
	return c, nil
}

// Status never performs network IO. Call Refresh at startup and run Run in a
// cancellable background context. Every check revalidates time and signature.
func (c *Client) Status() Status { c.mu.Lock(); defer c.mu.Unlock(); return c.status() }
func (c *Client) status() Status {
	out := Status{State: "missing", LastChecked: c.cached.Checked}
	if c.cached.Denial != "" {
		out.State = c.cached.Denial
		return out
	}
	if c.cached.Lease == nil {
		return out
	}
	claims, err := Verify(*c.cached.Lease, c.cfg.PublicKeys, c.cfg.Product, c.cfg.InstanceID, c.now())
	if err != nil {
		out.State = "invalid"
		if errors.Is(err, ErrLeaseExpired) {
			out.State = "lease_expired"
		}
		return out
	}
	out.State = "valid"
	out.Valid = true
	out.Claims = &claims
	return out
}

func (c *Client) save() error {
	if c.cfg.CachePath == "" {
		return nil
	}
	raw, _ := json.Marshal(c.cached)
	if err := atomicWrite(c.cfg.CachePath, raw); err != nil {
		return errors.New("cannot persist license state")
	}
	return nil
}

// Refresh falls back only on transport/protocol failure, bounded by the signed
// lease expiry. A recognized denial erases the old lease and persists rejection.
func (c *Client) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	return c.refresh(ctx)
}
func (c *Client) refresh(ctx context.Context) error {
	req := Request{Product: c.cfg.Product, Organization: c.cfg.Organization, Key: c.cfg.Key, InstanceID: c.cfg.InstanceID}
	raw, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL+"/v1/activate", bytes.NewReader(raw))
	if err != nil {
		return errors.New("license request failed")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	c.mu.Lock()
	c.nextAttempt = c.now().Add(time.Minute)
	c.mu.Unlock()
	if err != nil {
		return errors.New("license service unavailable")
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(raw) > 32768 {
		return errors.New("invalid license response")
	}
	var value Response
	if json.Unmarshal(raw, &value) != nil {
		return errors.New("invalid license response")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if response.StatusCode == http.StatusForbidden && knownDenial(value.Code) {
		c.cached.Lease = nil
		c.cached.Denial = value.Code
		c.cached.Checked = c.now()
		if err = c.save(); err != nil {
			return err
		}
		c.nextAttempt = c.now().Add(RefreshInterval)
		return errors.New("license denied")
	}
	if response.StatusCode != http.StatusOK || value.Lease == nil {
		return errors.New("license service unavailable")
	}
	claims, err := Verify(*value.Lease, c.cfg.PublicKeys, c.cfg.Product, c.cfg.InstanceID, c.now())
	if err != nil || claims.Organization != c.cfg.Organization {
		return errors.New("invalid license response")
	}
	c.cached.Lease = value.Lease
	c.cached.Denial = ""
	c.cached.Checked = c.now()
	if err = c.save(); err != nil {
		return err
	}
	c.nextAttempt = c.now().Add(RefreshInterval)
	return nil
}
func knownDenial(code string) bool {
	switch code {
	case "revoked", "suspended", "expired", "not_yet_valid", "invalid_key", "instance_limit", "released":
		return true
	}
	return false
}

// Run refreshes immediately, hourly on success, and once per minute after a
// transient failure. The caller owns cancellation and process shutdown.
func (c *Client) Run(ctx context.Context) {
	_ = c.Refresh(ctx)
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.mu.Lock()
			due := !c.now().Before(c.nextAttempt)
			c.mu.Unlock()
			if due {
				_ = c.Refresh(ctx)
			}
		}
	}
}

func (c *Client) Release(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	raw, _ := json.Marshal(Request{Product: c.cfg.Product, Organization: c.cfg.Organization, Key: c.cfg.Key, InstanceID: c.cfg.InstanceID})
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL+"/v1/release", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(r)
	if err != nil {
		return errors.New("release outcome unknown, reconcile the same instance")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("license release failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cached.Lease = nil
	c.cached.Denial = "released"
	c.cached.Checked = c.now()
	return c.save()
}

// Middleware protects new requests. Diagnostics and recovery must be routed
// separately by the host application. Already accepted work is unaffected.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.Status().Valid {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "license required", http.StatusPaymentRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}
