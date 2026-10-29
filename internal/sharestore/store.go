// Package sharestore persists secret records (MPC key shares, Paillier
// pre-parameters) encrypted at rest in a single signer's data directory.
//
// Each record is a separate file sealed with AES-256-GCM under a key derived
// from the signer's passphrase with Argon2id. Every file gets a fresh salt and
// nonce, and the record name is bound as associated data so files can't be
// swapped between records undetected.
package sharestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	formatVersion = 1
	fileExt       = ".enc"
	aadPrefix     = "thresholdvault/sharestore/v1/"
)

// KDFParams are the Argon2id cost parameters recorded in each file.
type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
}

// DefaultKDF follows the RFC 9106 second recommended option (64 MiB, t=3).
var DefaultKDF = KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}

var (
	ErrNotFound      = errors.New("sharestore: record not found")
	ErrDecrypt       = errors.New("sharestore: decryption failed (wrong passphrase or tampered file)")
	ErrInvalidName   = errors.New("sharestore: invalid record name")
	ErrEmptyPassword = errors.New("sharestore: passphrase must not be empty")

	// Names are slash-separated segments like "share/<wallet-id>".
	nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}(/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127})*$`)
)

type envelope struct {
	Version    int       `json:"version"`
	Name       string    `json:"name"`
	KDF        KDFParams `json:"kdf"`
	Salt       []byte    `json:"salt"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
}

// Store is an encrypted record store rooted at one directory.
type Store struct {
	dir        string
	passphrase []byte
	kdf        KDFParams
}

// Open creates (if needed) dir with 0700 permissions and returns a Store.
func Open(dir string, passphrase []byte) (*Store, error) {
	return OpenWithKDF(dir, passphrase, DefaultKDF)
}

// OpenWithKDF is Open with explicit KDF costs for newly written records
// (tests use cheaper parameters). Existing files keep their own parameters.
func OpenWithKDF(dir string, passphrase []byte, kdf KDFParams) (*Store, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassword
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sharestore: create dir: %w", err)
	}
	return &Store{dir: dir, passphrase: append([]byte(nil), passphrase...), kdf: kdf}, nil
}

func (s *Store) path(name string) (string, error) {
	if !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return filepath.Join(s.dir, filepath.FromSlash(name)+fileExt), nil
}

func (s *Store) deriveKey(salt []byte, p KDFParams) []byte {
	return argon2.IDKey(s.passphrase, salt, p.Time, p.Memory, p.Threads, 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Put encrypts and atomically writes plaintext under name, replacing any
// existing record.
func (s *Store) Put(name string, plaintext []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := newGCM(s.deriveKey(salt, s.kdf))
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	env := envelope{
		Version:    formatVersion,
		Name:       name,
		KDF:        s.kdf,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, []byte(aadPrefix+name)),
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Get reads and decrypts the record stored under name.
func (s *Store) Get(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("sharestore: corrupt record %s: %w", name, err)
	}
	if env.Version != formatVersion {
		return nil, fmt.Errorf("sharestore: unsupported format version %d", env.Version)
	}
	if env.Name != name {
		return nil, fmt.Errorf("sharestore: record %s claims to be %q", name, env.Name)
	}
	if env.KDF.Time == 0 || env.KDF.Memory < 8*1024 || env.KDF.Threads == 0 || len(env.Salt) < 16 {
		return nil, fmt.Errorf("sharestore: record %s has unsafe KDF parameters", name)
	}
	aead, err := newGCM(s.deriveKey(env.Salt, env.KDF))
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, []byte(aadPrefix+name))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// Has reports whether a record exists (without decrypting it).
func (s *Store) Has(name string) (bool, error) {
	p, err := s.path(name)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Delete removes a record. Deleting a missing record is not an error.
func (s *Store) Delete(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// List returns the names of records under prefix (e.g. "share/"), sorted.
func (s *Store) List(prefix string) ([]string, error) {
	var names []string
	root := filepath.Join(s.dir, filepath.FromSlash(strings.TrimSuffix(prefix, "/")))
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, fileExt) || strings.HasPrefix(d.Name(), ".tmp-") {
			return nil
		}
		rel, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(strings.TrimSuffix(rel, fileExt))
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}
