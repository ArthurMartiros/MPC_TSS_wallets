package sharestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

var testKDF = KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}

func open(t *testing.T, dir, pass string) *Store {
	t.Helper()
	s, err := OpenWithKDF(dir, []byte(pass), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := open(t, t.TempDir(), "correct horse")
	secret := []byte(`{"xi":"secret share"}`)
	if err := s.Put("share/w1", secret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("share/w1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q", got)
	}
}

func TestCiphertextDoesNotLeakPlaintext(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, "pw")
	secret := []byte("VERY-SECRET-SHARE-MATERIAL")
	if err := s.Put("share/w1", secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "share", "w1.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext found in file")
	}
}

func TestWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	if err := open(t, dir, "right").Put("share/w1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, dir, "wrong").Get("share/w1"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, "pw")
	if err := s.Put("share/w1", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "share", "w1.enc")
	raw, _ := os.ReadFile(path)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[0] ^= 0xff
	raw, _ = json.Marshal(env)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("share/w1"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

// A ciphertext copied over another record must not decrypt, even if the
// attacker also rewrites the envelope's name field (AAD binding).
func TestSwappedRecordsAreRejected(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, "pw")
	if err := s.Put("share/a", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("share/b", []byte("B")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "share", "a.enc"))
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Name = "share/b"
	raw, _ = json.Marshal(env)
	if err := os.WriteFile(filepath.Join(dir, "share", "b.enc"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("share/b"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestFreshSaltAndNoncePerWrite(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, "pw")
	read := func() envelope {
		raw, _ := os.ReadFile(filepath.Join(dir, "share", "w.enc"))
		var e envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	_ = s.Put("share/w", []byte("same"))
	e1 := read()
	_ = s.Put("share/w", []byte("same"))
	e2 := read()
	if bytes.Equal(e1.Salt, e2.Salt) || bytes.Equal(e1.Nonce, e2.Nonce) || bytes.Equal(e1.Ciphertext, e2.Ciphertext) {
		t.Fatal("salt/nonce reused across writes")
	}
}

func TestInvalidNames(t *testing.T) {
	s := open(t, t.TempDir(), "pw")
	for _, name := range []string{"", "../etc/passwd", "share/../../x", "/abs", "Share/w", "share//w", "share/w/"} {
		if err := s.Put(name, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: want ErrInvalidName, got %v", name, err)
		}
	}
}

func TestNotFoundAndHasDeleteList(t *testing.T) {
	s := open(t, t.TempDir(), "pw")
	if _, err := s.Get("share/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	for _, n := range []string{"share/w2", "share/w1", "preparams/p1"} {
		if err := s.Put(n, []byte(n)); err != nil {
			t.Fatal(err)
		}
	}
	names, err := s.List("share/")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"share/w1", "share/w2"}) {
		t.Fatalf("list = %v", names)
	}
	if ok, _ := s.Has("share/w1"); !ok {
		t.Fatal("Has = false")
	}
	if err := s.Delete("share/w1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Has("share/w1"); ok {
		t.Fatal("Has = true after delete")
	}
	if names, _ := s.List("nothing/"); len(names) != 0 {
		t.Fatalf("list of empty prefix = %v", names)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "signer")
	s := open(t, dir, "pw")
	if err := s.Put("share/w1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "share", "w1.enc"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}
}

func TestEmptyPassphraseRejected(t *testing.T) {
	if _, err := Open(t.TempDir(), nil); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("want ErrEmptyPassword, got %v", err)
	}
}
