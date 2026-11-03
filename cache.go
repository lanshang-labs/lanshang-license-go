package license

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".license-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

// LoadOrCreateInstance persists a random instance identity. Keep it across restarts
// and do not copy it into a different deployment. Publication is atomic.
func LoadOrCreateInstance(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return parseInstance(raw)
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	var bytes [24]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(bytes[:])
	f, err := os.CreateTemp(filepath.Dir(path), ".instance-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.WriteString(id)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err = os.Link(f.Name(), path); err != nil && !os.IsExist(err) {
		return "", err
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return parseInstance(raw)
}
func parseInstance(raw []byte) (string, error) {
	id := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 24 {
		return "", errors.New("invalid persisted instance identity")
	}
	return id, nil
}
