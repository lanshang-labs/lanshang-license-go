package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLeaseVerification(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	c := Claims{Product: "app", OrganizationID: "org", Organization: "Test", LicenseID: "lic", InstanceID: "inst", IssuedAt: now, ExpiresAt: now.Add(time.Hour), LicenseExpiresAt: now.Add(time.Hour)}
	signed, _ := Sign(c, "k", private)
	keys := map[string]ed25519.PublicKey{"k": public}
	if _, err := Verify(signed, keys, "app", "inst", now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, product, instance string
		now                     time.Time
	}{
		{"product", "other", "inst", now}, {"instance", "app", "other", now}, {"expired", "app", "inst", now.Add(time.Hour)}, {"future", "app", "inst", now.Add(-time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(signed, keys, tc.product, tc.instance, tc.now); err == nil {
				t.Fatal("accepted invalid binding/time")
			}
		})
	}
	signed.Payload += "x"
	if _, err := Verify(signed, keys, "app", "inst", now); err == nil {
		t.Fatal("tampering accepted")
	}
	c.ExpiresAt = now.Add(25 * time.Hour)
	c.LicenseExpiresAt = c.ExpiresAt
	signed, _ = Sign(c, "k", private)
	if _, err := Verify(signed, keys, "app", "inst", now); err == nil {
		t.Fatal("unbounded lease accepted")
	}
	c.ExpiresAt = now.Add(time.Hour)
	c.LicenseExpiresAt = now.Add(time.Minute)
	signed, _ = Sign(c, "k", private)
	if _, err := Verify(signed, keys, "app", "inst", now); err == nil {
		t.Fatal("license expiry ignored")
	}
}

func TestRefreshOutageDenialRestartAndRecovery(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	mode := "valid"
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input Request
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Fatal("bad request")
		}
		if mode == "outage" {
			w.WriteHeader(503)
			return
		}
		if mode == "revoked" {
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(Response{Code: "revoked"})
			return
		}
		lease, _ := Sign(Claims{Product: input.Product, OrganizationID: "org", Organization: input.Organization, LicenseID: "lic", InstanceID: input.InstanceID, IssuedAt: now, ExpiresAt: now.Add(2 * time.Hour), LicenseExpiresAt: now.Add(24 * time.Hour)}, "k", private)
		_ = json.NewEncoder(w).Encode(Response{Lease: &lease})
	}))
	defer service.Close()
	cfg := Config{ServerURL: service.URL, Product: "app", Organization: "Test", Key: "secret", InstanceID: "inst", PublicKeys: map[string]ed25519.PublicKey{"k": public}, CachePath: filepath.Join(t.TempDir(), "lease.json"), AllowHTTP: true}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if client.Status().Valid {
		t.Fatal("unactivated")
	}
	if err = client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !client.Status().Valid {
		t.Fatal("activation missing")
	}
	info, _ := os.Stat(cfg.CachePath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe cache permissions")
	}
	mode = "outage"
	if client.Refresh(context.Background()) == nil || !client.Status().Valid {
		t.Fatal("outage cache failure")
	}
	restarted, _ := New(cfg)
	if !restarted.Status().Valid {
		t.Fatal("restart lost valid lease")
	}
	restarted.now = func() time.Time { return now.Add(3 * time.Hour) }
	if restarted.Status().Valid {
		t.Fatal("expired offline lease accepted")
	}
	mode = "revoked"
	if client.Refresh(context.Background()) == nil || client.Status().Valid {
		t.Fatal("revoke ignored")
	}
	restarted, _ = New(cfg)
	if restarted.Status().State != "revoked" {
		t.Fatal("denial lost on restart")
	}
	mode = "outage"
	_ = restarted.Refresh(context.Background())
	if restarted.Status().Valid {
		t.Fatal("old lease revived")
	}
	mode = "valid"
	if err = restarted.Refresh(context.Background()); err != nil || !restarted.Status().Valid {
		t.Fatal("renewal recovery", err)
	}
	cfg.Key = "different"
	other, _ := New(cfg)
	if other.Status().Valid {
		t.Fatal("cross-license cache reuse")
	}
}

func TestInstancePublicationConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance")
	var wg sync.WaitGroup
	ids := make(chan string, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := LoadOrCreateInstance(path)
			if err != nil {
				t.Error(err)
			}
			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	expected := ""
	for id := range ids {
		if expected == "" {
			expected = id
		}
		if id != expected {
			t.Fatal("multiple identities")
		}
	}
}

func TestRedirectDoesNotLeakKey(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	c, err := New(Config{ServerURL: redirect.URL, Product: "app", Organization: "Test", Key: "secret", InstanceID: "inst", PublicKeys: map[string]ed25519.PublicKey{"k": public}, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Refresh(context.Background()) == nil || leaked {
		t.Fatal("redirect followed")
	}
}

func TestConfigurationAndDiagnostics(t *testing.T) {
	if _, err := New(Config{ServerURL: "http://example.com", AllowHTTP: true}); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := New(Config{ServerURL: "https://example.com", Product: "app", Organization: "Test", Key: "secret", InstanceID: "inst", PublicKeys: map[string]ed25519.PublicKey{"k": public}})
	w := httptest.NewRecorder()
	c.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unlicensed request") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 402 {
		t.Fatal(w.Code)
	}
}

func TestLocalStatusDoesNotWaitForRefresh(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(503) }))
	defer server.Close()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	client, err := New(Config{ServerURL: server.URL, Product: "app", Organization: "Test", Key: "secret", InstanceID: "inst", PublicKeys: map[string]ed25519.PublicKey{"k": public}, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = client.Refresh(context.Background()); close(done) }()
	<-entered
	statusDone := make(chan struct{})
	go func() { client.Status(); close(statusDone) }()
	select {
	case <-statusDone:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("local check blocked on remote request")
	}
	close(release)
	<-done
}
