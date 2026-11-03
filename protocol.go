// Package license provides local verification and bounded refresh of remote licenses.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const Format = "lanshang.lease.v1"
const RefreshInterval = time.Hour
const MaxLeaseDuration = 24 * time.Hour

type Claims struct {
	Product          string    `json:"product"`
	OrganizationID   string    `json:"organization_id"`
	Organization     string    `json:"organization"`
	LicenseID        string    `json:"license_id"`
	InstanceID       string    `json:"instance_id"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	LicenseExpiresAt time.Time `json:"license_expires_at"`
}

type Lease struct {
	Format    string `json:"format"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Request struct {
	Product      string `json:"product"`
	Organization string `json:"organization"`
	Key          string `json:"key"`
	InstanceID   string `json:"instance_id"`
}

type Response struct {
	Lease *Lease `json:"lease,omitempty"`
	Code  string `json:"code,omitempty"`
}

// Sign belongs on the licensing server. Never distribute its private key.
func Sign(claims Claims, keyID string, key ed25519.PrivateKey) (Lease, error) {
	if len(key) != ed25519.PrivateKeySize || keyID == "" {
		return Lease{}, errors.New("invalid signing identity")
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return Lease{}, err
	}
	return Lease{Format: Format, KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signingBytes(keyID, raw)))}, nil
}

func signingBytes(id string, payload []byte) []byte {
	return append([]byte(Format+"\n"+id+"\n"), payload...)
}

// Verify binds every lease to the expected product and deployment instance.
func Verify(lease Lease, keys map[string]ed25519.PublicKey, product, instance string, now time.Time) (Claims, error) {
	var c Claims
	key := keys[lease.KeyID]
	raw, a := base64.RawURLEncoding.DecodeString(lease.Payload)
	sig, b := base64.RawURLEncoding.DecodeString(lease.Signature)
	if lease.Format != Format || a != nil || b != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signingBytes(lease.KeyID, raw), sig) {
		return c, errors.New("invalid lease signature")
	}
	if json.Unmarshal(raw, &c) != nil || c.Product != product || c.InstanceID != instance || c.OrganizationID == "" || c.Organization == "" || c.LicenseID == "" || c.IssuedAt.After(now) || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > MaxLeaseDuration || c.ExpiresAt.After(c.LicenseExpiresAt) {
		return Claims{}, errors.New("invalid or expired lease")
	}
	return c, nil
}
